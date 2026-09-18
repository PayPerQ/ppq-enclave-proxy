/**
 * A second inbound port that expects a PROXY protocol header (v1 text as
 * nginx emits, or v2 binary as the NLB emits) before the TLS ClientHello, records the client address it names, and then hands the
 * connection to the ordinary HTTPS server so its TLS handshake and HTTP
 * parsing run exactly as they do on the plain inbound port.
 *
 * WHY A SEPARATE PORT, NOT A FLAG ON THE EXISTING ONE
 * --------------------------------------------------
 * The 443 path (enclave.ppq.ai) is fed by an NLB with client-IP preservation
 * OFF and an nginx arm that cannot enable `proxy_protocol` per SNI
 * (scripts/nginx-sni-split.conf, scripts/fleet/create-nlb.sh). It must keep
 * receiving a bare ClientHello. api.ppq.ai gets its own NLB (preservation ON),
 * its own nginx stream arm (`proxy_protocol on`), its own host socat and its
 * own vsock port, and THIS listener at the end of that chain. Nothing about
 * the first path changes; the enclave simply listens twice.
 *
 * TRUST
 * -----
 * A PROXY header is an unauthenticated claim about who the client is, so the
 * only safe design is one where nothing but nginx can reach this port. The
 * host-side socat that feeds it binds 127.0.0.1 (scripts/run-host.sh), so the
 * only process that can write into the vsock tunnel is nginx, and nginx
 * writes the address it observed on the accepted TCP connection — which, with
 * NLB preservation on, is the client's. Inside the enclave the port is
 * loopback too, and `req.socket.clientIp` is set by this module alone; no
 * header the client sends can populate it (passthrough.mjs strips every
 * inbound `x-ppq-client-ip*`).
 *
 * THE HANDOVER — what was verified, not assumed
 * ---------------------------------------------
 * The header is consumed with `socket.read(n)` for exactly the bytes the
 * parser asks for (6, then 16 and the address block for v2; one at a time to
 * the CRLF for v1), so exactly the header's bytes leave the stream and everything after it —
 * typically the ClientHello, which nginx sends in the same segment — stays in
 * the raw socket's readable buffer. The socket is then passed to
 * `tlsServer.emit('connection', socket)`, which is the listener `tls.Server`
 * registered in its own constructor and the same code path a socket from its
 * own `listen()` takes. Node's TLSSocket constructor drains a wrapped socket's
 * already-buffered bytes into the TLS handle before it starts reading the
 * handle (`initRead` in lib/_tls_wrap.js: "Socket already has some buffered
 * data - emulate receiving it"), so the ClientHello is not lost.
 * test/proxyListener.test.mjs sends header+ClientHello in ONE write and in two
 * and completes a real handshake and HTTP request both ways; that test is the
 * proof, and a Node upgrade that broke the property would fail it.
 *
 * The request handler sees the TLSSocket, not the raw socket. The address is
 * carried across in the server's 'secureConnection' event via
 * `tlsSocket._parent` (the raw socket, set by the TLSSocket constructor since
 * Node 0.11 and used by lib/_tls_wrap.js itself to proxy getpeername etc.),
 * with a fallback keyed by the raw socket's `remoteAddress:remotePort`, which
 * the TLSSocket reports identically. The listener is prepended so it runs
 * before the HTTP connection listener, i.e. before any request can be parsed.
 */
import net from 'node:net';
import { parseProxyHeader } from './proxyProtocol.mjs';

// Enough to tell "PROXY " (v1) from the v2 signature — they differ at byte 0,
// but 6 bytes is the shortest prefix that is a whole token of either grammar.
// From there the parser says how many more bytes to take: 16 and then the
// address block for v2, one at a time up to the CRLF for v1 (a v1 line has no
// length field, and reading past its CRLF would eat the ClientHello).
const FIRST_READ = 6;
// One state per HTTPS server, however many PROXY listeners feed it: the
// address maps and the single 'secureConnection' hook that reads them live
// on the server, so a second listener on the same server shares them.
const kState = Symbol('ppq.proxyProtocolState');

const peerKey = (s) => `${s.remoteAddress}:${s.remotePort}`;

/** The server's shared address maps, installing the hook on first use. */
function stateFor(tlsServer) {
  if (tlsServer[kState]) return tlsServer[kState];
  // Address by raw socket (primary) and by peer tuple (fallback; cleaned on
  // close). `viaRaw`/`viaPeer` record that a connection came through this
  // kind of listener WITH a client address: the request router uses that to
  // confine the transparent proxy to the api port, so enclave.ppq.ai's plain
  // port keeps answering 404 for routes the enclave does not serve even when
  // a passthrough host is configured, and no proxied request ever leaves
  // without the MAC'd client address horse-power rate-limits and geo-blocks
  // by. An addressless header (v1 UNKNOWN, v2 LOCAL) is accepted for the
  // handshake but is not "the api path" for this purpose.
  const state = { byRaw: new WeakMap(), byPeer: new Map(), viaRaw: new WeakSet(), viaPeer: new Set() };
  tlsServer[kState] = state;
  tlsServer.prependListener('secureConnection', (tlsSocket) => {
    const raw = tlsSocket._parent;
    let ip = raw ? state.byRaw.get(raw) : undefined;
    if (ip === undefined) ip = state.byPeer.get(peerKey(tlsSocket));
    if (ip) tlsSocket.clientIp = ip;
    const via = raw ? state.viaRaw.has(raw) : state.viaPeer.has(peerKey(tlsSocket));
    if (via) tlsSocket.viaProxyProtocol = true;
  });
  return state;
}

/**
 * @param {import('node:tls').Server} tlsServer  the https.Server to hand connections to
 * @param {object} opts
 * @param {number} opts.port
 * @param {string} [opts.host='127.0.0.1']
 * @param {number} [opts.headerTimeoutMs=5000]  a peer that sends no complete header
 *   within this is dropped (the header is the first thing on the wire; a legit
 *   nginx sends it with the ClientHello)
 * @param {(msg: string) => void} [opts.log]
 * @returns {Promise<net.Server>} resolves once the port is bound; rejects if it
 *   cannot be (EADDRINUSE, EACCES...). A caller that ignores the rejection
 *   would run with the api path silently missing, which is why start() awaits
 *   it and lets the process exit instead.
 */
export function listenWithProxyProtocol(tlsServer, { port, host = '127.0.0.1', headerTimeoutMs = 5000, log = () => {} } = {}) {
  if (!Number.isInteger(port) || port <= 0) return Promise.reject(new Error('listenWithProxyProtocol: port required'));

  const { byRaw, byPeer, viaRaw, viaPeer } = stateFor(tlsServer);

  const server = net.createServer(
    {
      // Mirror what the TLS server's own net.Server applies to accepted sockets,
      // so a socket that arrives here behaves like one from the plain port.
      allowHalfOpen: Boolean(tlsServer.allowHalfOpen),
      noDelay: Boolean(tlsServer.noDelay),
      keepAlive: Boolean(tlsServer.keepAlive),
    },
    (socket) => accept(socket),
  );

  function accept(socket) {
    let buf = null;
    let want = FIRST_READ;
    let settled = false;

    const finish = () => {
      settled = true;
      clearTimeout(timer);
      socket.removeListener('readable', onReadable);
      socket.removeListener('end', onEarlyEnd);
      socket.removeListener('error', onError);
    };
    const drop = (why) => {
      if (settled) return;
      finish();
      log(`proxy-protocol: ${why}; dropping connection`);
      socket.destroy();
    };
    const timer = setTimeout(() => drop('no complete header within timeout'), headerTimeoutMs);
    const onEarlyEnd = () => drop('connection ended before the header completed');
    const onError = () => drop('socket error before the header completed');

    function onReadable() {
      for (;;) {
        // read(n) hands back exactly n bytes when they are buffered, else null
        // and re-arms 'readable'. Nothing past the header is ever taken.
        const chunk = socket.read(want);
        if (chunk === null) return;
        buf = buf ? Buffer.concat([buf, chunk]) : chunk;
        const r = parseProxyHeader(buf);
        if (r.status === 'invalid') return drop('invalid header');
        if (r.status === 'incomplete') {
          want = r.need - buf.length;
          // A short read only happens once the peer has ended; 'end' drops it.
          if (want <= 0) return drop('header parser made no progress');
          continue;
        }
        if (buf.length !== r.headerLength) return drop('consumed past the header');
        finish();
        if (r.command === 'PROXY' && r.ip) {
          viaRaw.add(socket);
          viaPeer.add(peerKey(socket));
          byRaw.set(socket, r.ip);
          byPeer.set(peerKey(socket), r.ip);
          socket.once('close', () => { viaPeer.delete(peerKey(socket)); byPeer.delete(peerKey(socket)); });
          socket.proxyClientIp = r.ip;
        }
        // Hand the socket, with the ClientHello still buffered in it, to the
        // TLS server's own connection listener. See the header comment.
        tlsServer.emit('connection', socket);
        return;
      }
    }

    socket.on('readable', onReadable);
    socket.once('end', onEarlyEnd);
    socket.once('error', onError);
  }

  return new Promise((resolve, reject) => {
    let bound = false;
    server.on('error', (e) => {
      if (!bound) return reject(new Error(`proxy-protocol listener cannot bind ${host}:${port}: ${e.message}`));
      log(`proxy-protocol listener error: ${e.message}`);
    });
    server.listen(port, host, () => {
      bound = true;
      log(`proxy-protocol listener on ${host}:${port} (hands off to the TLS server)`);
      resolve(server);
    });
  });
}
