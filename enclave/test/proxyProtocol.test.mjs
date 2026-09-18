import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProxyV2, parseProxyV1, parseProxyHeader, buildProxyV2, buildProxyV1, formatIPv6, PROXY_V2_SIGNATURE, PROXY_V2_MAX_BLOCK } from '../src/proxyProtocol.mjs';

test('v2 TCP4: source address and port, exact header length', () => {
  const h = buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445);
  assert.equal(h.length, 28);
  const r = parseProxyV2(h);
  assert.deepEqual(r, { status: 'ok', version: 2, headerLength: 28, command: 'PROXY', family: 'TCP4', ip: '203.0.113.9', port: 51234 });
  assert.deepEqual(parseProxyHeader(h), r, 'the dispatcher picks v2 from the first byte');
});

test('v2 TCP6: RFC 5952 rendering of the source', () => {
  const h = buildProxyV2('2001:db8::1', 443, '2001:db8:0:0:0:0:0:2', 8445);
  assert.equal(h.length, 52);
  const r = parseProxyV2(h);
  assert.equal(r.status, 'ok');
  assert.equal(r.family, 'TCP6');
  assert.equal(r.ip, '2001:db8::1');
  assert.equal(r.port, 443);
  assert.equal(r.headerLength, 52);
});

test('v2 TCP6 with an IPv4-mapped source renders as the v4 literal', () => {
  const h = buildProxyV2('::ffff:198.51.100.7', 7, '::1', 8445);
  const r = parseProxyV2(h);
  assert.equal(r.status, 'ok');
  assert.equal(r.family, 'TCP6');
  assert.equal(r.ip, '198.51.100.7');
});

test('formatIPv6: longest zero run collapses, ties go to the first, single zero does not collapse', () => {
  const b = (groups) => {
    const out = Buffer.alloc(16);
    groups.forEach((g, i) => out.writeUInt16BE(g, i * 2));
    return out;
  };
  assert.equal(formatIPv6(b([0, 0, 0, 0, 0, 0, 0, 1])), '::1');
  assert.equal(formatIPv6(b([0, 0, 0, 0, 0, 0, 0, 0])), '::');
  assert.equal(formatIPv6(b([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1])), '2001:db8::1:0:0:1');
  assert.equal(formatIPv6(b([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1])), '2001:db8:0:1:1:1:1:1');
  assert.equal(formatIPv6(b([0xfe80, 0, 0, 0, 0x1ff, 0xfe23, 0x4567, 0x890a])), 'fe80::1ff:fe23:4567:890a');
});

test('the header bytes are exactly the documented layout', () => {
  const h = buildProxyV2('1.2.3.4', 0x1234, '5.6.7.8', 0x5678);
  assert.ok(h.subarray(0, 12).equals(PROXY_V2_SIGNATURE));
  assert.equal(h[12], 0x21, 'version 2 | PROXY');
  assert.equal(h[13], 0x11, 'INET | STREAM');
  assert.equal(h.readUInt16BE(14), 12);
  assert.deepEqual([...h.subarray(16, 20)], [1, 2, 3, 4]);
  assert.deepEqual([...h.subarray(20, 24)], [5, 6, 7, 8]);
  assert.equal(h.readUInt16BE(24), 0x1234);
  assert.equal(h.readUInt16BE(26), 0x5678);
});

test('LOCAL command: ok, no address', () => {
  const h = buildProxyV2(null, 0, null, 0, { command: 'LOCAL' });
  assert.equal(h.length, 16);
  assert.deepEqual(parseProxyV2(h), { status: 'ok', version: 2, headerLength: 16, command: 'LOCAL', family: 'UNSPEC' });
  // LOCAL with a non-empty (ignored) address block still reports the full length.
  const withBlock = Buffer.concat([h, Buffer.alloc(12, 0xaa)]);
  withBlock.writeUInt16BE(12, 14);
  assert.deepEqual(parseProxyV2(withBlock), { status: 'ok', version: 2, headerLength: 28, command: 'LOCAL', family: 'UNSPEC' });
});

test('TLVs after the addresses are skipped by the length field', () => {
  const tlvs = Buffer.from([0x01, 0x00, 0x05, 0x68, 0x32, 0x2c, 0x68, 0x31, 0x20, 0x00, 0x01, 0x07]);
  const h = buildProxyV2('203.0.113.9', 1, '10.0.0.5', 2, { tlvs });
  assert.equal(h.length, 28 + tlvs.length);
  const r = parseProxyV2(Buffer.concat([h, Buffer.from('CLIENTHELLO')]));
  assert.equal(r.status, 'ok');
  assert.equal(r.headerLength, 28 + tlvs.length, 'header length excludes trailing bytes and includes TLVs');
  assert.equal(r.ip, '203.0.113.9');
});

test('the v2-only parser rejects a v1 text header from the first byte', () => {
  assert.equal(parseProxyV2(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n')).status, 'invalid');
  assert.equal(parseProxyV2(Buffer.from('P')).status, 'invalid');
});

// ---- v1 (what nginx's stream proxy_protocol and curl --haproxy-protocol emit) ----

test('v1 TCP4: what nginx writes', () => {
  const h = buildProxyV1('TCP4', '203.0.113.9', '10.0.0.5', 51234, 8445);
  assert.equal(h.toString('latin1'), 'PROXY TCP4 203.0.113.9 10.0.0.5 51234 8445\r\n');
  const want = { status: 'ok', version: 1, headerLength: h.length, command: 'PROXY', family: 'TCP4', ip: '203.0.113.9', port: 51234 };
  assert.deepEqual(parseProxyV1(h), want);
  assert.deepEqual(parseProxyHeader(h), want, 'the dispatcher picks v1 from the first byte');
  // Trailing bytes (the ClientHello) do not change the header length.
  assert.deepEqual(parseProxyHeader(Buffer.concat([h, Buffer.from([0x16, 0x03, 0x01])])), want);
});

test("v1: curl --haproxy-protocol's exact shape parses", () => {
  const r = parseProxyHeader(Buffer.from('PROXY TCP4 127.0.0.1 127.0.0.1 54321 8445\r\n'));
  assert.equal(r.status, 'ok');
  assert.equal(r.version, 1);
  assert.equal(r.ip, '127.0.0.1');
  assert.equal(r.port, 54321);
  assert.equal(r.headerLength, 'PROXY TCP4 127.0.0.1 127.0.0.1 54321 8445\r\n'.length);
});

test('v1 TCP6: the address is taken as sent (no re-rendering)', () => {
  const r = parseProxyHeader(buildProxyV1('TCP6', '2001:db8::1', '2001:db8::2', 443, 8445));
  assert.equal(r.status, 'ok');
  assert.equal(r.family, 'TCP6');
  assert.equal(r.ip, '2001:db8::1');
  assert.equal(r.port, 443);
  // Longest legal TCP6 line: two full v6 literals and two 5-digit ports is
  // 104 bytes by the spec's own arithmetic (§2.1); 107 is the receiver's cap.
  const longest = buildProxyV1('TCP6', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 65535, 65535);
  assert.equal(longest.length, 104);
  assert.equal(parseProxyHeader(longest).status, 'ok');
});

test('v1 UNKNOWN: ok, no address; the rest of the line is ignored', () => {
  assert.deepEqual(parseProxyHeader(buildProxyV1('UNKNOWN')), { status: 'ok', version: 1, headerLength: 15, command: 'PROXY', family: 'UNSPEC' });
  const withJunk = Buffer.from('PROXY UNKNOWN ffff:f...f:ffff 65535 65535\r\n');
  assert.deepEqual(parseProxyHeader(withJunk), { status: 'ok', version: 1, headerLength: withJunk.length, command: 'PROXY', family: 'UNSPEC' });
});

test('v1: incomplete asks for exactly one more byte until the CRLF', () => {
  const h = buildProxyV1('TCP4', '203.0.113.9', '10.0.0.5', 51234, 8445);
  for (let n = 1; n < h.length; n += 1) {
    assert.deepEqual(parseProxyHeader(h.subarray(0, n)), { status: 'incomplete', need: n + 1 }, `at ${n} bytes`);
  }
  assert.deepEqual(parseProxyHeader(Buffer.alloc(0)), { status: 'incomplete', need: 1 });
});

test('v1: an over-long line, a CRLF past byte 107, or a malformed line is invalid', () => {
  assert.equal(parseProxyHeader(Buffer.from('PROXY TCP4 ' + 'x'.repeat(100))).status, 'invalid', '107 bytes without CRLF');
  assert.equal(parseProxyHeader(Buffer.from('PROXY TCP4 ' + '1'.repeat(100) + '\r\n')).status, 'invalid', 'CRLF beyond the cap');
  for (const line of [
    'PROXY TCP4 203.0.113.9 10.0.0.5 51234\r\n', // missing a port
    'PROXY TCP4 203.0.113.9 10.0.0.5 51234 8445 extra\r\n',
    'PROXY TCP4 2001:db8::1 10.0.0.5 51234 8445\r\n', // v6 in a TCP4 line
    'PROXY TCP6 203.0.113.9 2001:db8::2 51234 8445\r\n', // v4 in a TCP6 line
    'PROXY TCP4 203.0.113.9 10.0.0.5 65536 8445\r\n', // port range
    'PROXY TCP4 203.0.113.9 10.0.0.5 -1 8445\r\n',
    'PROXY TCP4 203.0.113.9 10.0.0.5 01 8445\r\n', // leading zero
    'PROXY TCP4  203.0.113.9 10.0.0.5 1 8445\r\n', // double space
    'PROXY UDP4 203.0.113.9 10.0.0.5 1 8445\r\n',
    'PROXY TCP4 203.0.113.9 10.0.0.5 1 8445\n', // bare LF is not a terminator: no CRLF within 107 -> needs more, then...
    'PROXY\r\n',
    'PROXY tcp4 203.0.113.9 10.0.0.5 1 8445\r\n',
    'PROXY TCP4 203.0.113.9 10.0.0.5 1 8445\x01\r\n',
  ]) {
    const r = parseProxyHeader(Buffer.from(line, 'latin1'));
    assert.ok(r.status === 'invalid' || (r.status === 'incomplete' && !line.endsWith('\r\n')), `${JSON.stringify(line)} -> ${r.status}`);
  }
});

test('the dispatcher: anything that starts with neither grammar is invalid at byte 0', () => {
  assert.equal(parseProxyHeader(Buffer.from([0x16])).status, 'invalid', 'a TLS record');
  assert.equal(parseProxyHeader(Buffer.from('GET / HTTP/1.1\r\n')).status, 'invalid');
  assert.equal(parseProxyHeader(Buffer.from('proxy tcp4')).status, 'invalid');
  assert.equal(parseProxyHeader('PROXY TCP4').status, 'invalid', 'not a buffer');
});

test('a bare TLS ClientHello (no header) is invalid, from the first byte', () => {
  assert.equal(parseProxyV2(Buffer.from([0x16, 0x03, 0x01, 0x00, 0xf8])).status, 'invalid');
});

test('bad signature, bad version, bad command, unsupported family are invalid', () => {
  const good = buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2);
  const mutate = (i, v) => {
    const c = Buffer.from(good);
    c[i] = v;
    return c;
  };
  assert.equal(parseProxyV2(mutate(11, 0x00)).status, 'invalid', 'signature');
  assert.equal(parseProxyV2(mutate(12, 0x11)).status, 'invalid', 'version 1 nibble');
  assert.equal(parseProxyV2(mutate(12, 0x22)).status, 'invalid', 'command 2');
  assert.equal(parseProxyV2(mutate(13, 0x12)).status, 'invalid', 'UDP4');
  assert.equal(parseProxyV2(mutate(13, 0x31)).status, 'invalid', 'unix stream');
  // Declared family needs more address bytes than the length field carries.
  const short = Buffer.from(good);
  short[13] = 0x21;
  assert.equal(parseProxyV2(short).status, 'invalid', 'TCP6 with a 12-byte block');
});

test('an impossible header is invalid from its first 16 bytes, never incomplete', () => {
  const fixed = (cmdByte, familyByte, len) => {
    const h = Buffer.alloc(16);
    PROXY_V2_SIGNATURE.copy(h, 0);
    h[12] = cmdByte;
    h[13] = familyByte;
    h.writeUInt16BE(len, 14);
    return h;
  };
  // Unsupported family claiming 65535 bytes: rejected now, not after 65 KB.
  assert.equal(parseProxyV2(fixed(0x21, 0x12, 65535)).status, 'invalid', 'UDP4 with max length');
  assert.equal(parseProxyV2(fixed(0x21, 0x31, 65535)).status, 'invalid', 'unix with max length');
  // Declared family needs more than the length field offers.
  assert.equal(parseProxyV2(fixed(0x21, 0x11, 4)).status, 'invalid', 'TCP4 with len 4');
  assert.equal(parseProxyV2(fixed(0x21, 0x21, 12)).status, 'invalid', 'TCP6 with len 12');
  // Above the block cap, for every command and family.
  assert.equal(PROXY_V2_MAX_BLOCK, 548);
  assert.equal(parseProxyV2(fixed(0x21, 0x11, PROXY_V2_MAX_BLOCK + 1)).status, 'invalid', 'TCP4 above cap');
  assert.equal(parseProxyV2(fixed(0x21, 0x00, 65535)).status, 'invalid', 'UNSPEC above cap');
  assert.equal(parseProxyV2(fixed(0x20, 0x00, 65535)).status, 'invalid', 'LOCAL above cap');
  // At the cap with a real block: still a header (TLVs are legal).
  const tlvs = Buffer.alloc(PROXY_V2_MAX_BLOCK - 12, 0);
  const atCap = buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2, { tlvs });
  assert.equal(atCap.readUInt16BE(14), PROXY_V2_MAX_BLOCK);
  assert.equal(parseProxyV2(atCap.subarray(0, 16)).status, 'incomplete', 'a legal length waits for its block');
  assert.equal(parseProxyV2(atCap).status, 'ok');
  // Legal families with legal lengths still wait for the block.
  assert.deepEqual(parseProxyV2(fixed(0x21, 0x11, 12)), { status: 'incomplete', need: 28 });
  assert.deepEqual(parseProxyV2(fixed(0x21, 0x21, 36)), { status: 'incomplete', need: 52 });
  assert.deepEqual(parseProxyV2(fixed(0x20, 0x00, 12)), { status: 'incomplete', need: 28 }, 'LOCAL keeps its block semantics');
});

test('UNSPEC family with PROXY command: ok, no address (spec says ignore)', () => {
  const h = buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2);
  h[13] = 0x00;
  assert.deepEqual(parseProxyV2(h), { status: 'ok', version: 2, headerLength: 28, command: 'PROXY', family: 'UNSPEC' });
});

test('truncated input is incomplete with the exact byte count needed', () => {
  const h = buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445);
  assert.deepEqual(parseProxyV2(Buffer.alloc(0)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 5)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 15)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 16)), { status: 'incomplete', need: 28 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 27)), { status: 'incomplete', need: 28 });
  assert.equal(parseProxyV2(h.subarray(0, 28)).status, 'ok');
});

test('never throws: garbage of every kind is invalid', () => {
  for (const input of [undefined, null, 'string', 42, {}, [], Buffer.alloc(100, 0xff), Buffer.alloc(16, 0)]) {
    assert.equal(parseProxyV2(input).status, 'invalid');
  }
});
