/**
 * PROXY protocol v2 header parser (HAProxy spec, "The PROXY protocol",
 * §2.2 binary header format). Pure: no I/O, never throws.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every hop in front of the enclave forwards raw TCP bytes — the NLB, nginx
 * `ssl_preread`, socat, vsock. None of them can put the client's address into
 * an HTTP header because none of them can see HTTP: TLS ends inside the
 * enclave. PROXY protocol is the one mechanism that works below TLS: the last
 * hop that knows the address (nginx, with `proxy_protocol on`) prepends a
 * small binary header to the connection, and the enclave reads it BEFORE
 * starting its TLS handshake. Only the api port speaks it — see
 * proxyListener.mjs for the trust argument and README "PROXY protocol on the
 * api port".
 *
 * WIRE FORMAT (v2 only; v1 is a text line and is rejected here on purpose,
 * because nginx never emits it and accepting two grammars doubles the surface)
 * ---------------------------------------------------------------------------
 *   bytes  0-11   signature  \r\n\r\n\0\r\nQUIT\n
 *   byte   12     high nibble = version (2), low nibble = command
 *                 (0x0 LOCAL: the sender's own connection, e.g. a health check;
 *                  0x1 PROXY: a relayed client connection)
 *   byte   13     high nibble = address family (0x1 INET, 0x2 INET6, 0x0 UNSPEC),
 *                 low nibble = transport (0x1 STREAM); 0x11 = TCP4, 0x21 = TCP6
 *   bytes  14-15  big-endian length of everything that follows (addresses + TLVs)
 *   then          src addr, dst addr, src port, dst port
 *                   INET:  4 + 4 + 2 + 2 = 12 bytes
 *                   INET6: 16 + 16 + 2 + 2 = 36 bytes
 *   then          optional TLVs, skipped by the length field
 *
 * Return shape:
 *   { status: 'incomplete', need }        fewer than `need` bytes so far
 *   { status: 'invalid' }                 not a v2 header, or a family this
 *                                         listener does not carry (UDP, unix)
 *   { status: 'ok', headerLength, command: 'PROXY'|'LOCAL',
 *     family: 'TCP4'|'TCP6'|'UNSPEC', ip?, port? }
 *
 * `headerLength` is the exact number of bytes the header occupies, so the
 * caller can hand every byte after it — the ClientHello — to TLS untouched.
 * `ip` is present only for a PROXY command over TCP4/TCP6. An IPv4-mapped IPv6
 * source (::ffff:a.b.c.d) is rendered as the IPv4 literal, which is how Node
 * itself reports such peers and what horse-power's `net.isIP` check expects.
 */

export const PROXY_V2_SIGNATURE = Buffer.from('\r\n\r\n\0\r\nQUIT\n', 'latin1');
const HEADER_FIXED = 16;
const CMD_LOCAL = 0x0;
const CMD_PROXY = 0x1;
const FAMILY_TCP4 = 0x11;
const FAMILY_TCP6 = 0x21;
const FAMILY_UNSPEC = 0x00;
const ADDR_LEN_TCP4 = 12;
const ADDR_LEN_TCP6 = 36;

const INVALID = Object.freeze({ status: 'invalid' });

/** Render 16 bytes as an RFC 5952 IPv6 literal (longest zero run → `::`). */
export function formatIPv6(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  // IPv4-mapped: ::ffff:a.b.c.d → the v4 literal.
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff) {
    return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  // Longest run of zero groups, length >= 2, first one wins on ties (RFC 5952 §4.2.3).
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

function formatIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/**
 * Parse the start of a connection. Feed it whatever has arrived so far; on
 * 'incomplete' read up to `need` bytes in total and call again.
 */
export function parseProxyV2(buf) {
  if (!Buffer.isBuffer(buf)) return INVALID;
  // Reject as early as the bytes allow: a v1 text header or a bare ClientHello
  // differs from the signature in its first byte(s).
  const sigLen = Math.min(buf.length, PROXY_V2_SIGNATURE.length);
  if (!buf.subarray(0, sigLen).equals(PROXY_V2_SIGNATURE.subarray(0, sigLen))) return INVALID;
  if (buf.length < HEADER_FIXED) return { status: 'incomplete', need: HEADER_FIXED };

  const verCmd = buf[12];
  if (verCmd >> 4 !== 2) return INVALID;
  const cmd = verCmd & 0x0f;
  if (cmd !== CMD_LOCAL && cmd !== CMD_PROXY) return INVALID;

  const family = buf[13];
  const len = buf.readUInt16BE(14);
  const headerLength = HEADER_FIXED + len;
  if (buf.length < headerLength) return { status: 'incomplete', need: headerLength };

  if (cmd === CMD_LOCAL) {
    // A LOCAL connection is the proxy's own (health check); the address block,
    // whatever it contains, must be ignored per spec.
    return { status: 'ok', headerLength, command: 'LOCAL', family: 'UNSPEC' };
  }

  if (family === FAMILY_TCP4) {
    if (len < ADDR_LEN_TCP4) return INVALID;
    return {
      status: 'ok',
      headerLength,
      command: 'PROXY',
      family: 'TCP4',
      ip: formatIPv4(buf.subarray(16, 20)),
      port: buf.readUInt16BE(24),
    };
  }
  if (family === FAMILY_TCP6) {
    if (len < ADDR_LEN_TCP6) return INVALID;
    return {
      status: 'ok',
      headerLength,
      command: 'PROXY',
      family: 'TCP6',
      ip: formatIPv6(buf.subarray(16, 32)),
      port: buf.readUInt16BE(48),
    };
  }
  if (family === FAMILY_UNSPEC) {
    // Spec: the receiver MUST accept UNSPEC and ignore the addresses. The
    // connection proceeds without a client address, exactly like LOCAL.
    return { status: 'ok', headerLength, command: 'PROXY', family: 'UNSPEC' };
  }
  // UDP, unix sockets, or a nibble no version of the spec defines.
  return INVALID;
}

function ipv4Bytes(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`not an IPv4 literal: ${ip}`);
  return Buffer.from(parts.map((p) => Number(p)));
}

function ipv6Bytes(ip) {
  // Expand `::`, then each group to 16 bits. An embedded v4 tail is accepted.
  let s = ip;
  let v4tail = null;
  const lastColon = s.lastIndexOf(':');
  if (s.includes('.', lastColon)) {
    v4tail = ipv4Bytes(s.slice(lastColon + 1));
    s = `${s.slice(0, lastColon + 1)}${v4tail.readUInt16BE(0).toString(16)}:${v4tail.readUInt16BE(2).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) throw new Error(`not an IPv6 literal: ${ip}`);
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) throw new Error(`not an IPv6 literal: ${ip}`);
  const groups = [...head, ...Array(missing).fill('0'), ...tail].map((g) => parseInt(g, 16));
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(g, i * 2));
  return out;
}

/**
 * Build a v2 PROXY header (for tests and for anyone emulating nginx). `ip`
 * decides the family; `tlvs` (a Buffer) is appended inside the length field.
 */
export function buildProxyV2(ip, port, dstIp, dstPort, { command = 'PROXY', tlvs = Buffer.alloc(0) } = {}) {
  if (command === 'LOCAL') {
    const h = Buffer.alloc(HEADER_FIXED);
    PROXY_V2_SIGNATURE.copy(h, 0);
    h[12] = 0x20 | CMD_LOCAL;
    h[13] = FAMILY_UNSPEC;
    h.writeUInt16BE(0, 14);
    return h;
  }
  const v6 = ip.includes(':');
  const src = v6 ? ipv6Bytes(ip) : ipv4Bytes(ip);
  const dst = v6 ? ipv6Bytes(dstIp) : ipv4Bytes(dstIp);
  const ports = Buffer.alloc(4);
  ports.writeUInt16BE(port, 0);
  ports.writeUInt16BE(dstPort, 2);
  const body = Buffer.concat([src, dst, ports, tlvs]);
  const h = Buffer.alloc(HEADER_FIXED);
  PROXY_V2_SIGNATURE.copy(h, 0);
  h[12] = 0x20 | CMD_PROXY;
  h[13] = v6 ? FAMILY_TCP6 : FAMILY_TCP4;
  h.writeUInt16BE(body.length, 14);
  return Buffer.concat([h, body]);
}
