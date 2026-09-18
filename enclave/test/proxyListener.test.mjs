// End-to-end: a real https.Server, a real TLS handshake, and the PROXY
// protocol listener in front of it. The point under test is the handover —
// that bytes buffered behind the header (the ClientHello) reach the TLS
// server intact — so the header and the ClientHello are delivered in ONE
// write and, separately, in two, through a small relay that owns the raw
// socket to the listener.
//
// Needs `openssl` for a throwaway self-signed certificate; skipped without it.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import net from 'node:net';
import { listenWithProxyProtocol } from '../src/proxyListener.mjs';
import { buildProxyV2 } from '../src/proxyProtocol.mjs';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
const skip = !haveOpenssl() && 'openssl not available';

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

function getJson(port, path = '/who') {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port, path, rejectUnauthorized: false, agent: false, servername: 'localhost', timeout: 5000 },
      (res) => {
        let b = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { b += d; });
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch (e) { reject(e); } });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end();
  });
}

/**
 * A plain TCP relay in front of the PROXY port. It waits for the client's
 * first chunk (the ClientHello — a TLS client always sends it as one write),
 * then opens the connection to the listener and delivers the PROXY header and
 * that chunk either concatenated in ONE write, or as two writes separated by a
 * pause long enough for the listener to have consumed the header first.
 */
function startRelay(targetPort, header, { split }) {
  const relay = net.createServer((client) => {
    client.once('data', (hello) => {
      const up = net.connect(targetPort, '127.0.0.1', () => {
        if (split) {
          up.write(header);
          setTimeout(() => { up.write(hello); client.pipe(up); up.pipe(client); }, 60);
        } else {
          up.write(Buffer.concat([header, hello]));
          client.pipe(up);
          up.pipe(client);
        }
      });
      up.on('error', () => client.destroy());
      client.on('error', () => up.destroy());
      client.on('close', () => up.destroy());
      up.on('close', () => client.destroy());
    });
  });
  return new Promise((resolve) => relay.listen(0, '127.0.0.1', () => resolve(relay)));
}

/** Connect raw, send `bytes` (or nothing), resolve when the peer closes; reject after 3s. */
function expectDropped(port, bytes) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => { if (bytes) s.write(bytes); });
    const t = setTimeout(() => { s.destroy(); reject(new Error('listener kept the connection open')); }, 3000);
    s.on('error', () => {});
    s.on('close', () => { clearTimeout(t); resolve(); });
  });
}

let dir;
let server;
let plainPort;
let ppPort;
let ppServer;
const logs = [];
const handovers = []; // readableLength of each raw socket at the moment the TLS server received it
const secureParents = [];

before(async () => {
  if (skip) return;
  dir = mkdtempSync(join(tmpdir(), 'pp-listener-'));
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { stdio: 'pipe' });
  server = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
    // What server.mjs reads: req.socket is the TLSSocket.
    const body = JSON.stringify({
      clientIp: req.socket.clientIp ?? null,
      remoteAddress: req.socket.remoteAddress,
      isTls: typeof req.socket.getPeerCertificate === 'function',
    });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  // Runs BEFORE tls.Server's own connection listener (prepended), so it sees
  // the raw socket's buffer exactly as it is handed over.
  server.prependListener('connection', (raw) => handovers.push(raw.readableLength));
  server.on('secureConnection', (tlsSocket) => secureParents.push(tlsSocket._parent));
  plainPort = await freePort();
  await new Promise((r) => server.listen(plainPort, '127.0.0.1', r));
  ppPort = await freePort();
  ppServer = listenWithProxyProtocol(server, { port: ppPort, host: '127.0.0.1', headerTimeoutMs: 300, log: (m) => logs.push(m) });
  await new Promise((r) => ppServer.once('listening', r));
});

after(async () => {
  if (skip) return;
  await new Promise((r) => ppServer.close(r));
  await new Promise((r) => server.close(r));
  rmSync(dir, { recursive: true, force: true });
});

test('header + ClientHello in ONE write: handshake completes and req.socket.clientIp is the PROXY source (v4)', { skip }, async () => {
  const header = buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445);
  const relay = await startRelay(ppPort, header, { split: false });
  try {
    handovers.length = 0;
    const { status, body } = await getJson(relay.address().port);
    assert.equal(status, 200);
    assert.equal(body.clientIp, '203.0.113.9');
    assert.equal(body.remoteAddress, '127.0.0.1', 'the TCP peer is still the relay; the address came from the header');
    assert.equal(body.isTls, true);
    // The proof of the handover: the ClientHello was sitting in the raw
    // socket's readable buffer when tls.Server received it, and the handshake
    // above still succeeded.
    assert.equal(handovers.length, 1);
    assert.ok(handovers[0] > 0, `expected buffered ClientHello at handover, saw readableLength=${handovers[0]}`);
  } finally {
    relay.close();
  }
});

test('header, then the ClientHello in a later write: same result', { skip }, async () => {
  const header = buildProxyV2('198.51.100.23', 40000, '10.0.0.5', 8445);
  const relay = await startRelay(ppPort, header, { split: true });
  try {
    handovers.length = 0;
    const { status, body } = await getJson(relay.address().port);
    assert.equal(status, 200);
    assert.equal(body.clientIp, '198.51.100.23');
    assert.equal(handovers.length, 1);
    assert.equal(handovers[0], 0, 'nothing was buffered yet; TLS read the ClientHello from the handle afterwards');
  } finally {
    relay.close();
  }
});

test('IPv6 source (one write)', { skip }, async () => {
  const header = buildProxyV2('2001:db8:85a3::8a2e:370:7334', 443, '2001:db8::2', 8445);
  const relay = await startRelay(ppPort, header, { split: false });
  try {
    const { body } = await getJson(relay.address().port);
    assert.equal(body.clientIp, '2001:db8:85a3::8a2e:370:7334');
  } finally {
    relay.close();
  }
});

test('IPv4-mapped IPv6 source arrives as the v4 literal', { skip }, async () => {
  const header = buildProxyV2('::ffff:192.0.2.44', 443, '::ffff:10.0.0.5', 8445);
  const relay = await startRelay(ppPort, header, { split: false });
  try {
    const { body } = await getJson(relay.address().port);
    assert.equal(body.clientIp, '192.0.2.44');
  } finally {
    relay.close();
  }
});

test('LOCAL header (a health check): handshake works, no clientIp', { skip }, async () => {
  const header = buildProxyV2(null, 0, null, 0, { command: 'LOCAL' });
  const relay = await startRelay(ppPort, header, { split: false });
  try {
    const { status, body } = await getJson(relay.address().port);
    assert.equal(status, 200);
    assert.equal(body.clientIp, null);
  } finally {
    relay.close();
  }
});

test('the ordinary port is untouched: no header expected, no clientIp', { skip }, async () => {
  const { status, body } = await getJson(plainPort);
  assert.equal(status, 200);
  assert.equal(body.clientIp, null);
  assert.equal(body.remoteAddress, '127.0.0.1');
});

test('a bare ClientHello on the PROXY port (no header) is dropped', { skip }, async () => {
  // The first byte of a TLS record is 0x16, which cannot start the signature.
  await assert.rejects(getJson(ppPort), /disconnected before secure TLS|socket hang up|ECONNRESET|EPIPE|timeout/i);
  assert.ok(logs.some((m) => m.includes('invalid header')), logs.join('\n'));
});

test('a v1 text header is dropped', { skip }, async () => {
  logs.length = 0;
  await expectDropped(ppPort, Buffer.from('PROXY TCP4 203.0.113.9 10.0.0.5 51234 8445\r\n'));
  assert.ok(logs.some((m) => m.includes('invalid header')), logs.join('\n'));
});

test('a header that never completes is dropped at the timeout', { skip }, async () => {
  logs.length = 0;
  const t0 = Date.now();
  await expectDropped(ppPort, null);
  assert.ok(Date.now() - t0 >= 250, 'dropped by the header timer, not immediately');
  assert.ok(logs.some((m) => m.includes('timeout')), logs.join('\n'));
  logs.length = 0;
  // Twelve good signature bytes and then silence: still incomplete, still dropped.
  await expectDropped(ppPort, buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2).subarray(0, 12));
  assert.ok(logs.some((m) => m.includes('timeout')), logs.join('\n'));
});

test('a peer that ends before the header completes is dropped without waiting', { skip }, async () => {
  logs.length = 0;
  const t0 = Date.now();
  await new Promise((resolve, reject) => {
    const s = net.connect(ppPort, '127.0.0.1', () => s.end(buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2).subarray(0, 20)));
    const t = setTimeout(() => { s.destroy(); reject(new Error('listener kept the connection open')); }, 3000);
    s.on('error', () => {});
    s.on('close', () => { clearTimeout(t); resolve(); });
  });
  assert.ok(Date.now() - t0 < 250, 'dropped on end, not on the timer');
  assert.ok(logs.some((m) => m.includes('ended before')), logs.join('\n'));
});

test('the address rides across on tlsSocket._parent, which is the raw net.Socket', { skip }, async () => {
  // Every TLSSocket the server saw above wrapped a raw net.Socket — the
  // private link proxyListener.mjs relies on. A Node upgrade that removed it
  // fails here, not silently in production.
  assert.ok(secureParents.length > 0);
  for (const p of secureParents) assert.ok(p instanceof net.Socket, 'tlsSocket._parent must be the raw net.Socket');
});

test('keep-alive: two requests on one PROXY connection both see the address', { skip }, async () => {
  const header = buildProxyV2('203.0.113.77', 51234, '10.0.0.5', 8445);
  const relay = await startRelay(ppPort, header, { split: false });
  try {
    const agent = new https.Agent({ keepAlive: true, maxSockets: 1, rejectUnauthorized: false });
    const one = () => new Promise((resolve, reject) => {
      const req = https.request({ host: '127.0.0.1', port: relay.address().port, path: '/who', agent, servername: 'localhost' }, (res) => {
        let b = '';
        res.on('data', (d) => { b += d; });
        res.on('end', () => resolve(JSON.parse(b)));
      });
      req.on('error', reject);
      req.end();
    });
    const a = await one();
    const b = await one();
    assert.equal(a.clientIp, '203.0.113.77');
    assert.equal(b.clientIp, '203.0.113.77');
    agent.destroy();
  } finally {
    relay.close();
  }
});
