import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import {
  createPassthrough,
  enclaveClientIpMac,
  isEnclaveRoute,
  outboundHeaders,
  responseHeaders,
  rewritePath,
} from '../src/passthrough.mjs';

// The proxy is exercised over plain HTTP against an in-process fake
// horse-power. Everything that matters — the per-request path decision, byte
// transparency, streaming, trailers, upgrades, failure shape — is independent
// of the TLS wrapping the real tunnel adds.

const servers = [];
after(async () => {
  // Node's default agent keeps connections alive, and server.close() waits
  // for them; drop them first or the runner never exits.
  for (const s of servers) {
    s.closeAllConnections?.();
    await new Promise((r) => s.close(r));
  }
});

function listen(server) {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

/** A fake horse-power that records what it received and answers per path. */
async function fakeHp() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const path = req.url.split('?')[0];
      if (path === '/echo') {
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-hp-custom': 'yes',
          'access-control-allow-origin': '*',
          'set-cookie': ['a=1', 'b=2'],
        });
        return res.end(JSON.stringify({ method: req.method, url: req.url, bytes: body.length, text: body.toString('utf8') }));
      }
      if (path === '/health') return res.end('hp-health');
      if (path === '/stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('data: one\n\n');
        setTimeout(() => res.write('data: two\n\n'), 60);
        setTimeout(() => res.end('data: [DONE]\n\n'), 120);
        return;
      }
      if (path === '/trailers') {
        res.writeHead(200, { 'content-type': 'text/plain', trailer: 'x-usage' });
        res.write('body');
        res.addTrailers({ 'x-usage': 'prompt=1' });
        return res.end();
      }
      if (path === '/status') {
        res.writeHead(418, { 'content-type': 'application/json' });
        return res.end('{"error":"teapot"}');
      }
      res.writeHead(404);
      res.end('hp-404');
    });
  });
  server.on('upgrade', (req, socket, head) => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, upgrade: true });
    if (req.url === '/ws/deny') {
      socket.end('HTTP/1.1 403 Forbidden\r\ncontent-length: 6\r\n\r\ndenied');
      return;
    }
    if (req.url === '/ws/accept-hop') {
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade, x-internal-hop\r\nX-Internal-Hop: gone\r\nKeep-Alive: timeout=5\r\nX-Hp-Ws: 1\r\n\r\n',
      );
      socket.on('data', (d) => socket.write(Buffer.concat([Buffer.from('echo:'), d])));
      socket.on('end', () => socket.destroy());
      return;
    }
    if (req.url === '/ws/deny-hop') {
      socket.end(
        'HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nTrailer: x-usage\r\nTE: trailers\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nConnection: x-internal-hop\r\nX-Internal-Hop: gone\r\nX-Hp-Note: kept\r\n\r\ndenied',
      );
      return;
    }
    if (req.url === '/ws/deny-chunked') {
      // The shape Express produces for a JSON 4xx on an upgrade: chunked.
      socket.end(
        'HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nX-Hp-Note: kept\r\n\r\n' +
          '8\r\n{"a":1}\n\r\n0\r\n\r\n',
      );
      return;
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Hp-Ws: 1\r\n\r\n');
    if (head.length) socket.write(Buffer.concat([Buffer.from('echo:'), head]));
    socket.on('data', (d) => socket.write(Buffer.concat([Buffer.from('echo:'), d])));
    // http.Server hands over half-open-capable sockets; a real WebSocket
    // server closes on the peer's FIN, so the fake does too.
    socket.on('end', () => socket.destroy());
  });
  const port = await listen(server);
  return { port, seen };
}

/** The enclave side: an HTTP server whose router mirrors server.mjs's check. */
async function enclaveFront(passthrough) {
  const server = http.createServer((req, res) => {
    if (!isEnclaveRoute(req.method, req.url)) return passthrough.handle(req, res);
    res.writeHead(200, { 'content-type': 'application/json', 'x-served-by': 'enclave' });
    res.end('{"enclave":true}');
  });
  server.on('upgrade', (req, socket, head) => passthrough.upgrade(req, socket, head));
  return listen(server);
}

/** Poll `pred` until true or `ms` elapse; the failure names the condition. */
async function waitFor(pred, what, ms = 3000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`timed out waiting for ${what}`);
}

function request(port, { method = 'GET', path = '/', headers = {}, body, agent = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent }, (res) => {
      const chunks = [];
      const arrivals = [];
      res.on('data', (c) => {
        chunks.push(c);
        arrivals.push(Date.now());
      });
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          trailers: res.trailers,
          body: Buffer.concat(chunks).toString('utf8'),
          arrivals,
        }),
      );
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('the routing table: only the enclave routes stay, any method on anything else is proxied', () => {
  assert.equal(isEnclaveRoute('POST', '/v1/chat/completions'), true);
  assert.equal(isEnclaveRoute('POST', '/chat/completions?x=1'), true);
  assert.equal(isEnclaveRoute('OPTIONS', '/v1/chat/completions'), true);
  assert.equal(isEnclaveRoute('GET', '/health'), true);
  assert.equal(isEnclaveRoute('GET', '/attestation?nonce=ab'), true);
  assert.equal(isEnclaveRoute('POST', '/acme/csr'), true);
  // Wrong method on an enclave path goes to horse-power, as api.ppq.ai does today.
  assert.equal(isEnclaveRoute('GET', '/v1/chat/completions'), false);
  assert.equal(isEnclaveRoute('POST', '/health'), false);
  assert.equal(isEnclaveRoute('GET', '/v1/models'), false);
  assert.equal(isEnclaveRoute('POST', '/v1/messages'), false);
  assert.equal(isEnclaveRoute('DELETE', '/keys/abc'), false);
  assert.equal(isEnclaveRoute('GET', '/hp/health'), false);
  assert.equal(rewritePath('/hp/health?x=1'), '/health?x=1');
  assert.equal(rewritePath('/v1/models'), '/v1/models');
});

test('outbound headers: hop-by-hop, connection-named, IP claims and x-ppq-client-ip* are stripped; host replaced', () => {
  const out = outboundHeaders(
    {
      host: 'api.ppq.ai',
      authorization: 'Bearer k',
      'content-type': 'application/json',
      connection: 'keep-alive, x-custom-hop',
      'x-custom-hop': 'gone',
      'keep-alive': 'timeout=5',
      'transfer-encoding': 'chunked',
      'x-forwarded-for': '1.2.3.4',
      'x-client-ip': '1.2.3.4',
      'cf-connecting-ip': '1.2.3.4',
      forwarded: 'for=1.2.3.4',
      'x-ppq-client-ip': '9.9.9.9',
      'x-ppq-client-ip-mac': 'deadbeef',
      'x-request-id': 'abc',
      trailer: 'x-usage',
    },
    { host: 'backend.example' },
  );
  assert.deepEqual(out, {
    authorization: 'Bearer k',
    'content-type': 'application/json',
    'x-request-id': 'abc',
    trailer: 'x-usage',
    host: 'backend.example',
  });
});

test('outbound headers: the MAC pair is added only when the enclave knows the address; upgrade keeps its headers', () => {
  const out = outboundHeaders(
    { connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-key': 'k' },
    { host: 'h', clientIp: '203.0.113.9', mac: 'abc', keepUpgrade: true },
  );
  assert.deepEqual(out, {
    connection: 'Upgrade',
    upgrade: 'websocket',
    'sec-websocket-key': 'k',
    host: 'h',
    'x-ppq-client-ip': '203.0.113.9',
    'x-ppq-client-ip-mac': 'abc',
  });
  assert.equal(outboundHeaders({}, { host: 'h', clientIp: '203.0.113.9' })['x-ppq-client-ip'], undefined);
});

test('enclaveClientIpMac is HMAC-SHA256 hex over "ip|minute" (mirrored in horse-power)', () => {
  const expected = createHmac('sha256', 's3cret').update('203.0.113.9|29827762').digest('hex');
  assert.equal(enclaveClientIpMac('203.0.113.9', 29827762, 's3cret'), expected);
});

test('response headers drop what Node manages and what the upstream Connection header nominates', () => {
  assert.deepEqual(
    responseHeaders({
      connection: 'close, x-internal-hop',
      'x-internal-hop': 'gone',
      'keep-alive': 'x',
      'transfer-encoding': 'chunked',
      te: 'trailers',
      upgrade: 'h2c',
      'proxy-authenticate': 'Basic',
      'proxy-connection': 'close',
      trailer: 'x-usage',
      'x-a': '1',
    }),
    { trailer: 'x-usage', 'x-a': '1' },
  );
});

test('a proxied request reaches horse-power verbatim and the answer comes back verbatim', async () => {
  const hp = await fakeHp();
  const events = [];
  const pt = createPassthrough({
    host: 'api.ppq.ai',
    port: hp.port,
    requestImpl: http.request,
    onEvent: (c) => events.push(c),
  });
  const front = await enclaveFront(pt);
  const r = await request(front, {
    method: 'PUT',
    path: '/echo?q=1&r=2',
    headers: { 'content-type': 'text/plain', 'x-request-id': 'rid-1', 'x-forwarded-for': '6.6.6.6' },
    body: 'hello hp',
  });
  assert.equal(r.status, 200);
  assert.equal(r.headers['x-hp-custom'], 'yes');
  assert.equal(r.headers['access-control-allow-origin'], '*');
  assert.deepEqual(r.headers['set-cookie'], ['a=1', 'b=2']);
  assert.deepEqual(JSON.parse(r.body), { method: 'PUT', url: '/echo?q=1&r=2', bytes: 8, text: 'hello hp' });
  const got = hp.seen[0];
  assert.equal(got.headers.host, 'api.ppq.ai');
  assert.equal(got.headers['x-request-id'], 'rid-1');
  assert.equal(got.headers['x-forwarded-for'], undefined);
  assert.equal(got.headers['x-ppq-client-ip'], undefined);
  assert.deepEqual(events, []);
  assert.equal(pt.inflight(), 0);
});

test('non-2xx from horse-power passes through untouched', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/status' });
  assert.equal(r.status, 418);
  assert.equal(r.body, '{"error":"teapot"}');
});

test('the decision is per request: /v1/models then a chat call on ONE keep-alive connection', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const a = await request(front, { path: '/echo', agent });
    const b = await request(front, { method: 'POST', path: '/v1/chat/completions', agent, body: '{}' });
    const c = await request(front, { path: '/echo', agent });
    assert.equal(a.status, 200);
    assert.equal(b.headers['x-served-by'], 'enclave');
    assert.equal(b.body, '{"enclave":true}');
    assert.equal(c.status, 200);
    // Exactly the two proxied requests reached horse-power; the chat never did.
    assert.deepEqual(
      hp.seen.map((s) => s.url),
      ['/echo', '/echo'],
    );
  } finally {
    agent.destroy();
  }
});

test('OPTIONS and HEAD on a proxied route go to horse-power; OPTIONS on a chat path stays in the enclave', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  await request(front, { method: 'OPTIONS', path: '/keys' });
  await request(front, { method: 'HEAD', path: '/echo' });
  const own = await request(front, { method: 'OPTIONS', path: '/v1/chat/completions' });
  assert.deepEqual(
    hp.seen.map((s) => `${s.method} ${s.url}`),
    ['OPTIONS /keys', 'HEAD /echo'],
  );
  assert.equal(own.headers['x-served-by'], 'enclave');
});

test('/hp/health is rewritten to horse-power /health', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/hp/health' });
  assert.equal(r.body, 'hp-health');
  assert.equal(hp.seen[0].url, '/health');
});

test('a stream is relayed as it arrives, not buffered', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/stream' });
  assert.equal(r.body, 'data: one\n\ndata: two\n\ndata: [DONE]\n\n');
  assert.ok(r.arrivals.length >= 2, `expected progressive chunks, got ${r.arrivals.length}`);
  assert.ok(r.arrivals[r.arrivals.length - 1] - r.arrivals[0] >= 50, 'chunks should be spread over time');
});

test('trailers survive the hop', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/trailers' });
  assert.equal(r.headers.trailer, 'x-usage');
  assert.equal(r.body, 'body');
  assert.equal(r.trailers['x-usage'], 'prompt=1');
});

test('a large body streams through byte-exact', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const big = Buffer.alloc(5 * 1024 * 1024, 'x');
  const r = await request(front, { method: 'POST', path: '/echo', headers: { 'content-type': 'application/octet-stream' }, body: big });
  assert.equal(JSON.parse(r.body).bytes, big.length);
});

test('horse-power unreachable: a content-free 502 and one report, never a hang', async () => {
  // Grab a free port and release it, so nothing listens there.
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const deadPort = probe.address().port;
  await new Promise((r) => probe.close(r));
  const events = [];
  const pt = createPassthrough({ host: 'h', port: deadPort, requestImpl: http.request, onEvent: (c) => events.push(c) });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/v1/models' });
  assert.equal(r.status, 502);
  assert.deepEqual(JSON.parse(r.body), { error: { message: 'upstream unavailable', type: 'server_error', code: 502 } });
  assert.deepEqual(events, ['passthrough_unreachable']);
  assert.equal(pt.inflight(), 0);
});

test('the client-IP MAC pair is added when the socket carries an address and a secret is configured', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({
    host: 'h',
    port: hp.port,
    requestImpl: http.request,
    secret: 's3cret',
    now: () => 29827762 * 60_000 + 15_000,
  });
  const server = http.createServer((req, res) => {
    req.socket.clientIp = '203.0.113.9'; // what the PROXY-protocol listener will set
    pt.handle(req, res);
  });
  const front = await listen(server);
  await request(front, { path: '/echo', headers: { 'x-ppq-client-ip': '1.1.1.1', 'x-ppq-client-ip-mac': 'forged' } });
  const got = hp.seen[0].headers;
  assert.equal(got['x-ppq-client-ip'], '203.0.113.9');
  assert.equal(got['x-ppq-client-ip-mac'], enclaveClientIpMac('203.0.113.9', 29827762, 's3cret'));
});

test('an Upgrade is spliced: 101 relayed, early bytes delivered, both directions flow', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write(
    'GET /ws/transcribe HTTP/1.1\r\nHost: api.ppq.ai\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\nearly',
  );
  let buf = '';
  const until = (pred) =>
    new Promise((resolve) => {
      const check = () => {
        if (pred(buf)) resolve();
      };
      sock.on('data', (d) => {
        buf += d.toString('utf8');
        check();
      });
      check();
    });
  await until((b) => b.includes('echo:early'));
  assert.ok(buf.startsWith('HTTP/1.1 101 Switching Protocols\r\n'));
  assert.ok(/x-hp-ws: 1/i.test(buf));
  sock.write('later');
  await until((b) => b.includes('echo:later'));
  sock.destroy();
  const seen = hp.seen.find((s) => s.upgrade);
  assert.equal(seen.headers.host, 'h');
  assert.equal(seen.headers.upgrade, 'websocket');
});

test('an Upgrade horse-power declines is relayed as its own answer', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/deny HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  assert.ok(buf.startsWith('HTTP/1.1 403 Forbidden\r\n'), buf);
  assert.ok(buf.endsWith('denied'), buf);
});

test('the inflight cap answers 503 without touching horse-power', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request, maxInflight: 0 });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/echo' });
  assert.equal(r.status, 503);
  assert.equal(hp.seen.length, 0);
});

test('a declined upgrade with a chunked body is relayed decoded, without transfer framing', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/deny-chunked HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  const [head, body] = buf.split('\r\n\r\n');
  assert.ok(head.startsWith('HTTP/1.1 403 Forbidden\r\n'), head);
  assert.ok(!/transfer-encoding/i.test(head), head);
  assert.ok(/x-hp-note: kept/i.test(head), head);
  assert.ok(/connection: close/i.test(head), head);
  assert.equal(body, '{"a":1}\n');
  assert.equal(pt.inflight(), 0);
});

test('horse-power unreachable on an upgrade: the 502 body reaches the client before the close', async () => {
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const deadPort = probe.address().port;
  await new Promise((r) => probe.close(r));
  const events = [];
  const pt = createPassthrough({ host: 'h', port: deadPort, requestImpl: http.request, onEvent: (c) => events.push(c) });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/transcribe HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  assert.ok(buf.startsWith('HTTP/1.1 502 Bad Gateway\r\n'), buf);
  assert.ok(buf.endsWith('"code":502}}'), buf);
  assert.deepEqual(events, ['passthrough_unreachable']);
  assert.equal(pt.inflight(), 0);
});

test('the inflight cap applies to upgrades too, and is released when the conversation ends', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request, maxInflight: 1 });
  const front = await enclaveFront(pt);
  const open = (path) => {
    const s = net.connect(front, '127.0.0.1');
    return once(s, 'connect').then(() => {
      s.write(`GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`);
      return s;
    });
  };
  const first = await open('/ws/transcribe');
  let a = '';
  first.on('data', (d) => (a += d.toString('utf8')));
  await waitFor(() => a.startsWith('HTTP/1.1 101'), 'the 101 on the first upgrade');
  assert.equal(pt.inflight(), 1);
  // Second upgrade while the first is open: refused, horse-power untouched.
  const second = await open('/ws/transcribe');
  let b = '';
  second.on('data', (d) => (b += d.toString('utf8')));
  await once(second, 'close');
  assert.ok(b.startsWith('HTTP/1.1 503 Service Unavailable\r\n'), b);
  assert.equal(hp.seen.filter((s) => s.upgrade).length, 1);
  // Closing the first releases the slot.
  first.destroy();
  await waitFor(() => pt.inflight() === 0, 'the slot to be released');
});

test('a client that closes before the handshake releases the slot and reports nothing', async () => {
  // An upstream that accepts the connection and never answers, so the
  // handshake is still pending when the client leaves.
  // Reading (resume) matters: a paused raw socket never sees the peer's FIN.
  const silent = net.createServer((c) => {
    c.resume();
    c.on('end', () => c.destroy());
  });
  const silentPort = await listen(silent);
  const events = [];
  const pt = createPassthrough({ host: 'h', port: silentPort, requestImpl: http.request, onEvent: (c) => events.push(c) });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/transcribe HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  await waitFor(() => pt.inflight() === 1, 'the upgrade to be counted');
  sock.destroy();
  await waitFor(() => pt.inflight() === 0, 'the slot to be released after the client left');
  await new Promise((r) => setTimeout(r, 30));
  assert.deepEqual(events, []);
});

test('a declined upgrade never advertises trailers or other hop-by-hop fields', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/deny-hop HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  const head = buf.split('\r\n\r\n')[0];
  assert.ok(head.startsWith('HTTP/1.1 403 Forbidden\r\n'), head);
  const names = head.split('\r\n').slice(1).map((l) => l.split(':')[0].toLowerCase());
  for (const bad of ['trailer', 'te', 'x-internal-hop', 'keep-alive', 'proxy-authenticate']) {
    assert.ok(!names.includes(bad), `${bad} leaked: ${head}`);
  }
  assert.ok(names.includes('x-hp-note'), head);
  assert.ok(names.includes('connection'), head);
});

test('a relayed 101 keeps connection/upgrade but drops nominated and other hop-by-hop fields', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/accept-hop HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await waitFor(() => buf.includes('\r\n\r\n'), 'the 101 head');
  const head = buf.split('\r\n\r\n')[0];
  const names = head.split('\r\n').slice(1).map((l) => l.split(':')[0].toLowerCase());
  assert.ok(head.startsWith('HTTP/1.1 101'), head);
  assert.ok(names.includes('connection') && names.includes('upgrade') && names.includes('x-hp-ws'), head);
  assert.ok(!names.includes('x-internal-hop') && !names.includes('keep-alive'), head);
  sock.write('ping');
  await waitFor(() => buf.includes('echo:ping'), 'the echo through the splice');
  sock.destroy();
});
