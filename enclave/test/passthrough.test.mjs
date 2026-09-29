import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import { EventEmitter } from 'node:events';
import {
  createPassthrough,
  enclaveClientIpMac,
  failureReason,
  hasNoBody,
  CONNECT_TIMEOUT_MS,
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
    if (req.url === '/ws/deny-slow') {
      // Head now, body later: longer than the proxy's connect timeout in the test.
      socket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\n');
      setTimeout(() => socket.end('denied'), 150);
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
  // Decisions (decisions.mjs) is served in-enclave on all three of its paths.
  assert.equal(isEnclaveRoute('POST', '/v1/decisions'), true);
  assert.equal(isEnclaveRoute('POST', '/decisions'), true);
  assert.equal(isEnclaveRoute('POST', '/v1/systemone'), true);
  assert.equal(isEnclaveRoute('OPTIONS', '/v1/decisions'), true);
  assert.equal(isEnclaveRoute('GET', '/v1/decisions'), false);
  // The decisions catalog listing stays horse-power's.
  assert.equal(isEnclaveRoute('GET', '/v1/decisions/models'), false);
  // Tinfoil private/* (#210): the client-sealed relay and the two helper
  // routes the SDK fetches are served here...
  assert.equal(isEnclaveRoute('POST', '/private/v1/chat/completions'), true);
  assert.equal(isEnclaveRoute('POST', '/private/chat/completions'), true);
  assert.equal(isEnclaveRoute('OPTIONS', '/private/v1/chat/completions'), true);
  assert.equal(isEnclaveRoute('GET', '/private/attestation'), true);
  assert.equal(isEnclaveRoute('POST', '/private/attestation'), true);
  assert.equal(isEnclaveRoute('GET', '/private/.well-known/hpke-keys'), true);
  // ...while document conversion and the legacy aliases keep going to horse-power.
  assert.equal(isEnclaveRoute('POST', '/private/v1/convert/file'), false);
  assert.equal(isEnclaveRoute('POST', '/encrypted/v1/chat/completions'), false);
  assert.equal(isEnclaveRoute('POST', '/tinfoil/v1/chat/completions'), false);
  assert.equal(isEnclaveRoute('GET', '/private/v1/chat/completions'), false);
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
  const pt = createPassthrough({ host: 'h', port: deadPort, requestImpl: http.request, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/v1/models' });
  assert.equal(r.status, 502);
  assert.deepEqual(JSON.parse(r.body), { error: { message: 'upstream unavailable', type: 'server_error', code: 502 } });
  // The reason rides the report as a token: the enclave has no console in
  // production, so this is the only place the errno can be read.
  assert.deepEqual(events, [['passthrough_unreachable', { reason: 'ECONNREFUSED', reused_socket: false, attempts: 1 }]]);
  assert.equal(pt.inflight(), 0);
});

/**
 * A request implementation whose first call fails the way a pooled socket
 * that horse-power already closed fails — ECONNRESET on a reused socket before
 * any status line — and whose later calls are real http.request calls.
 */
function staleThenReal(failures, code = 'ECONNRESET') {
  const calls = [];
  const impl = (opts, cb) => {
    calls.push({ agent: opts.agent, method: opts.method });
    if (calls.length <= failures) {
      const fake = new EventEmitter();
      fake.reusedSocket = true;
      fake.setTimeout = () => {};
      fake.destroy = () => {};
      fake.end = () => queueMicrotask(() => fake.emit('error', Object.assign(new Error('read ECONNRESET'), { code })));
      fake.write = () => true;
      fake.once = fake.on.bind(fake);
      // pipe() target contract: writable-ish. The body is empty for these
      // methods, so end() is what fires.
      fake.emit = EventEmitter.prototype.emit;
      fake.on('pipe', () => {});
      return fake;
    }
    return http.request(opts, cb);
  };
  return { impl, calls };
}

test('a stale pooled socket on a GET is retried once, on a fresh connection, and the client never sees it', async () => {
  const hp = await fakeHp();
  const events = [];
  const { impl, calls } = staleThenReal(1);
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: impl, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/echo' });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).method, 'GET');
  assert.equal(calls.length, 2);
  // The retry must not draw from the pool that produced the stale socket.
  assert.equal(calls[1].agent, false);
  assert.deepEqual(events, []);
  assert.equal(pt.inflight(), 0);
});

test('a stale socket is retried only once: a second failure is reported with attempts: 2', async () => {
  const hp = await fakeHp();
  const events = [];
  const { impl, calls } = staleThenReal(2);
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: impl, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const r = await request(front, { path: '/echo' });
  assert.equal(r.status, 502);
  assert.equal(calls.length, 2);
  assert.deepEqual(events, [['passthrough_unreachable', { reason: 'ECONNRESET', reused_socket: true, attempts: 2 }]]);
  assert.equal(pt.inflight(), 0);
});

test('a POST on a stale socket is never retried: its body may already have been read', async () => {
  const hp = await fakeHp();
  const events = [];
  const { impl, calls } = staleThenReal(1);
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: impl, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const r = await request(front, { method: 'POST', path: '/echo', body: '{"a":1}' });
  assert.equal(r.status, 502);
  assert.equal(calls.length, 1);
  assert.deepEqual(events, [['passthrough_unreachable', { reason: 'ECONNRESET', reused_socket: true, attempts: 1 }]]);
  assert.equal(pt.inflight(), 0);
});

test('a GET that declares a body is not retried: the body cannot be replayed', async () => {
  const hp = await fakeHp();
  const events = [];
  const { impl, calls } = staleThenReal(1);
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: impl, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const r = await request(front, { method: 'GET', path: '/echo', headers: { 'content-length': '6' }, body: 'framed' });
  assert.equal(r.status, 502);
  assert.equal(calls.length, 1);
  assert.deepEqual(events, [['passthrough_unreachable', { reason: 'ECONNRESET', reused_socket: true, attempts: 1 }]]);
});

test('hasNoBody: only an absent or zero content-length with no transfer-encoding counts as bodiless', () => {
  assert.equal(hasNoBody({}), true);
  assert.equal(hasNoBody({ 'content-length': '0' }), true);
  assert.equal(hasNoBody({ 'content-length': '12' }), false);
  assert.equal(hasNoBody({ 'transfer-encoding': 'chunked' }), false);
  assert.equal(hasNoBody({ 'content-length': '0', 'transfer-encoding': 'chunked' }), false);
  assert.equal(hasNoBody(undefined), false);
});

test('the connect timeout outlasts the Azure front end and stays inside the nginx arm and the NLB', () => {
  // Azure App Service closes an idle request at 230 s with its own 502; the
  // nginx stream arm's proxy_timeout is 300 s; the NLB's idle timeout is 350 s.
  // The enclave must be the second to give up, never the first: a 60 s value
  // cut real 63–186 s image generations that horse-power then completed and billed.
  assert.ok(CONNECT_TIMEOUT_MS > 230_000, `must outlast the Azure front end (got ${CONNECT_TIMEOUT_MS})`);
  assert.ok(CONNECT_TIMEOUT_MS < 300_000, `must stay inside the nginx arm's proxy_timeout (got ${CONNECT_TIMEOUT_MS})`);
});

test('the default connect timeout is the exported constant, and a caller can still shorten it', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  assert.equal(pt.connectTimeoutMs(), CONNECT_TIMEOUT_MS);
  const short = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request, connectTimeoutMs: 40 });
  assert.equal(short.connectTimeoutMs(), 40);
});

test('failureReason is a closed vocabulary: errno codes pass, messages become tokens, anything else is OTHER', () => {
  assert.equal(failureReason(Object.assign(new Error('x'), { code: 'ECONNRESET' })), 'ECONNRESET');
  assert.equal(failureReason(Object.assign(new Error('x'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })), 'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(failureReason(new Error('connect timeout')), 'CONNECT_TIMEOUT');
  assert.equal(failureReason(new Error('socket hang up')), 'SOCKET_HANG_UP');
  assert.equal(failureReason(new Error('upstream said: the prompt was "secret"')), 'OTHER');
  assert.equal(failureReason(Object.assign(new Error('x'), { code: 'not a code' })), 'OTHER');
  assert.equal(failureReason(null), 'OTHER');
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
  const pt = createPassthrough({ host: 'h', port: deadPort, requestImpl: http.request, onEvent: (c, f) => events.push([c, f]) });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/transcribe HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  assert.ok(buf.startsWith('HTTP/1.1 502 Bad Gateway\r\n'), buf);
  assert.ok(buf.endsWith('"code":502}}'), buf);
  assert.deepEqual(events, [['passthrough_unreachable', { reason: 'ECONNREFUSED', reused_socket: false, attempts: 1 }]]);
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

test('a slow declined-upgrade body is not cut by the connect timeout, and no 502 is appended', async () => {
  const hp = await fakeHp();
  const events = [];
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request, connectTimeoutMs: 40, onEvent: (c) => events.push(c) });
  const front = await enclaveFront(pt);
  const sock = net.connect(front, '127.0.0.1');
  await once(sock, 'connect');
  sock.write('GET /ws/deny-slow HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  let buf = '';
  sock.on('data', (d) => (buf += d.toString('utf8')));
  await once(sock, 'close');
  assert.ok(buf.startsWith('HTTP/1.1 403 Forbidden\r\n'), buf);
  assert.ok(buf.endsWith('\r\n\r\ndenied'), buf);
  assert.ok(!buf.includes('502'), buf);
  assert.deepEqual(events, []);
  assert.equal(pt.inflight(), 0);
});

// ---------------------------------------------------------------------------
// PII gate on /v1/responses and /v1/messages (`pii_redaction`). Fictional
// fixtures only. Asserted at the fake horse-power (what it received) and at
// the client (what came back).
// ---------------------------------------------------------------------------

const PII_PROMPT = 'Hi, I am Jane Roe, write to jane.roe@example.com';
const PII_SURFACE = /Jane Roe|jane\.roe@example\.com/;
const PII_PLACEHOLDER = /⟦[A-Z]+_[0-9]+⟧/;
const PII_MINUTE = 29827762;
const PII_SECRET = 'pii-test-secret';

/** In-process detector: finds the two fictional surfaces; `mode` = ok | fail. */
function fakePiiDetector() {
  const calls = [];
  const d = {
    mode: 'ok',
    calls,
    async detect(texts) {
      calls.push(texts);
      if (d.mode === 'fail') throw Object.assign(new Error('pii detector failed: timeout'), { reason: 'timeout' });
      const spans = texts.map((t) => {
        const out = [];
        for (const [s, cls] of [['Jane Roe', 'PERSON'], ['jane.roe@example.com', 'EMAIL']]) {
          let i = -1;
          while ((i = t.indexOf(s, i + 1)) !== -1) out.push({ start: i, end: i + s.length, cls });
        }
        return out;
      });
      return { spans, calls: 1 };
    },
  };
  return d;
}

/** The pieces of the redacted prompt the fake model quotes back. */
function quoted(text) {
  const m = /^Hi, I am (.+), write to (.+)$/.exec(text);
  return m ? { who: m[1], email: m[2] } : { who: '', email: '' };
}

const sseEvent = (ev, named) => `${named ? `event: ${ev.type}\n` : ''}data: ${JSON.stringify(ev)}\n\n`;
const pieces = (s) => [...s].join('').match(/[\s\S]{1,3}/gu) ?? [];

/** Fake horse-power for the PII routes: echoes the (redacted) prompt as each dialect would. */
async function fakePiiHp() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks);
      let body = {};
      try { body = JSON.parse(raw.toString('utf8')); } catch { /* leave {} */ }
      seen.push({ url: req.url, headers: req.headers, raw });
      const path = req.url.split('?')[0];
      let text = '';
      if (path === '/v1/responses') text = typeof body.input === 'string' ? body.input : '';
      if (path === '/v1/messages') text = typeof body.messages?.at(-1)?.content === 'string' ? body.messages.at(-1).content : '';
      const { who, email } = quoted(text);
      const said = `You said: ${text}`;
      const args = JSON.stringify({ to: email, name: who });
      let out;
      let type = 'application/json';
      if (path === '/v1/responses' && !body.stream) {
        out = JSON.stringify({ id: 'resp_1', object: 'response', output_text: said, output: [
          { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: said }] },
          { type: 'function_call', call_id: 'c1', name: 'send_email', arguments: args },
        ] });
      } else if (path === '/v1/responses') {
        type = 'text/event-stream';
        out = '';
        for (const d of pieces(said)) out += sseEvent({ type: 'response.output_text.delta', item_id: 'm1', output_index: 0, content_index: 0, delta: d }, true);
        out += sseEvent({ type: 'response.output_text.done', item_id: 'm1', output_index: 0, content_index: 0, text: said }, true);
        for (const d of pieces(args)) out += sseEvent({ type: 'response.function_call_arguments.delta', item_id: 'f1', output_index: 1, delta: d }, true);
        out += sseEvent({ type: 'response.function_call_arguments.done', item_id: 'f1', output_index: 1, arguments: args }, true);
        out += sseEvent({ type: 'response.completed', response: { id: 'resp_1', output: [{ type: 'message', content: [{ type: 'output_text', text: said }] }] } }, true);
      } else if (path === '/v1/messages' && !body.stream) {
        out = JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', content: [
          { type: 'text', text: said },
          { type: 'tool_use', id: 't1', name: 'send_email', input: { to: email, name: who } },
        ] });
      } else if (path === '/v1/messages') {
        type = 'text/event-stream';
        out = sseEvent({ type: 'message_start', message: { id: 'msg_1', type: 'message', role: 'assistant', content: [] } }, true);
        out += sseEvent({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }, true);
        for (const d of pieces(said)) out += sseEvent({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: d } }, true);
        out += sseEvent({ type: 'content_block_stop', index: 0 }, true);
        out += sseEvent({ type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't1', name: 'send_email', input: {} } }, true);
        for (const d of pieces(args)) out += sseEvent({ type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: d } }, true);
        out += sseEvent({ type: 'content_block_stop', index: 1 }, true);
        out += sseEvent({ type: 'message_stop' }, true);
      } else {
        res.writeHead(404);
        return res.end('hp-404');
      }
      res.writeHead(200, { 'content-type': type, 'content-length': Buffer.byteLength(out) });
      // Five bytes at a time: events and UTF-8 sequences split anywhere.
      const bytes = Buffer.from(out, 'utf8');
      for (let i = 0; i < bytes.length; i += 5) {
        res.write(bytes.subarray(i, i + 5));
        await new Promise((r) => setImmediate(r));
      }
      res.end();
    });
  });
  const port = await listen(server);
  return { port, seen };
}

async function piiSetup({ authorizeStatus = 200, bufferCap, secret = PII_SECRET } = {}) {
  const hp = await fakePiiHp();
  const detector = fakePiiDetector();
  const authorizes = [];
  const pt = createPassthrough({
    host: 'api.ppq.ai',
    port: hp.port,
    requestImpl: http.request,
    secret,
    now: () => PII_MINUTE * 60_000 + 15_000,
    pii: {
      authorize: async (req, meta) => {
        authorizes.push({ meta, credit: req.headers['x-credit-id'] });
        return authorizeStatus === 200
          ? { ok: true, status: 200, body: { authorized: true } }
          : { ok: false, status: authorizeStatus, body: { error: { message: 'insufficient balance', code: authorizeStatus } } };
      },
      detector: () => detector,
      ...(bufferCap ? { bufferCap } : {}),
    },
  });
  const front = await enclaveFront(pt);
  const post = (path, body, headers = {}) =>
    request(front, {
      method: 'POST',
      path,
      headers: { 'content-type': 'application/json', 'x-credit-id': 'credit-under-test', ...headers },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  return { hp, detector, authorizes, pt, post };
}

const expectedMac = (n, id) => createHmac('sha256', PII_SECRET).update(`${n}|${id}|${PII_MINUTE}`).digest('hex');

test('pii gate: flag absent forwards the original bytes, never parsed, nothing asked', async () => {
  const s = await piiSetup();
  // Odd spacing and key order: any re-serialisation would show.
  const raw = `{ "model" :"openai/gpt-5",   "input":"${PII_PROMPT}" ,"note":"pii_redaction" }`;
  const r = await s.post('/v1/responses', raw);
  assert.equal(r.status, 200);
  assert.ok(s.hp.seen[0].raw.equals(Buffer.from(raw)), 'byte-identical at horse-power');
  assert.equal(s.detector.calls.length, 0);
  assert.equal(s.authorizes.length, 0);
  assert.equal(s.hp.seen[0].headers['x-ppq-pii-calls'], undefined);
  assert.equal(s.pt.inflight(), 0);
});

test('pii gate: false forwards the body without the field and without redaction', async () => {
  const s = await piiSetup();
  const r = await s.post('/v1/messages', { model: 'claude-x', pii_redaction: false, messages: [{ role: 'user', content: PII_PROMPT }] });
  assert.equal(r.status, 200);
  const got = JSON.parse(s.hp.seen[0].raw.toString('utf8'));
  assert.ok(!Object.hasOwn(got, 'pii_redaction'));
  assert.equal(got.messages[0].content, PII_PROMPT);
  assert.equal(s.detector.calls.length, 0);
  assert.equal(s.authorizes.length, 0);
});

test('pii gate: a non-boolean flag or a private model is a 400 and horse-power is not reached', async () => {
  const s = await piiSetup();
  const bad = await s.post('/v1/responses', { model: 'm', input: 'x', pii_redaction: 'yes' });
  assert.equal(bad.status, 400);
  assert.equal(JSON.parse(bad.body).error.code, 'pii_redaction_invalid');
  const priv = await s.post('/v1/messages', { model: 'private/some-model', pii_redaction: true, messages: [] });
  assert.equal(priv.status, 400);
  assert.equal(JSON.parse(priv.body).error.code, 'pii_redaction_unsupported_model');
  assert.equal(s.hp.seen.length, 0);
  assert.equal(s.authorizes.length, 0);
  assert.equal(s.pt.inflight(), 0);
});

test('pii gate: Responses non-stream — no surface upstream, text and function_call args restored, signed count', async () => {
  const s = await piiSetup();
  const r = await s.post('/v1/responses', { model: 'openai/gpt-5', pii_redaction: true, input: PII_PROMPT }, {
    'x-request-id': 'rid-pii-1', 'x-ppq-pii-calls': '0', 'x-ppq-pii-calls-mac': 'forged',
  });
  assert.equal(r.status, 200, r.body);
  const got = s.hp.seen[0];
  assert.doesNotMatch(got.raw.toString('utf8'), PII_SURFACE);
  assert.doesNotMatch(got.raw.toString('utf8'), /pii_redaction/);
  assert.match(JSON.parse(got.raw.toString('utf8')).input, PII_PLACEHOLDER);
  assert.equal(got.headers['x-request-id'], 'rid-pii-1');
  assert.equal(got.headers['x-ppq-pii-calls'], '1', 'the client value is replaced');
  assert.equal(got.headers['x-ppq-pii-calls-mac'], expectedMac(1, 'rid-pii-1'));
  const body = JSON.parse(r.body);
  assert.equal(body.output_text, `You said: ${PII_PROMPT}`);
  assert.equal(body.output[0].content[0].text, `You said: ${PII_PROMPT}`);
  assert.deepEqual(JSON.parse(body.output[1].arguments), { to: 'jane.roe@example.com', name: 'Jane Roe' });
  assert.equal(r.headers['content-length'], undefined, 'the restored body is not framed by the upstream length');
  assert.deepEqual(s.authorizes.map((a) => a.meta.requestId), ['rid-pii-1']);
  assert.equal(s.pt.inflight(), 0);
});

test('pii gate: Messages non-stream — text and tool_use input restored', async () => {
  const s = await piiSetup();
  const r = await s.post('/v1/messages', { model: 'claude-x', pii_redaction: true, messages: [{ role: 'user', content: PII_PROMPT }] });
  assert.equal(r.status, 200, r.body);
  assert.doesNotMatch(s.hp.seen[0].raw.toString('utf8'), PII_SURFACE);
  const body = JSON.parse(r.body);
  assert.equal(body.content[0].text, `You said: ${PII_PROMPT}`);
  assert.deepEqual(body.content[1].input, { to: 'jane.roe@example.com', name: 'Jane Roe' });
});

test('pii gate: Responses and Messages streams are restored across split events', async () => {
  const s = await piiSetup();
  const events = (sse) => sse.split('\n').filter((l) => l.startsWith('data: ')).map((l) => JSON.parse(l.slice(6)));

  const rr = await s.post('/v1/responses', { model: 'openai/gpt-5', stream: true, pii_redaction: true, input: PII_PROMPT });
  assert.equal(rr.status, 200);
  assert.doesNotMatch(rr.body, PII_PLACEHOLDER);
  const re = events(rr.body);
  assert.equal(re.filter((e) => e.type === 'response.output_text.delta').map((e) => e.delta).join(''), `You said: ${PII_PROMPT}`);
  assert.deepEqual(JSON.parse(re.filter((e) => e.type === 'response.function_call_arguments.delta').map((e) => e.delta).join('')),
    { to: 'jane.roe@example.com', name: 'Jane Roe' });
  assert.match(rr.body, /^event: response\.output_text\.delta$/m, 'event lines are kept');

  const mr = await s.post('/v1/messages', { model: 'claude-x', stream: true, pii_redaction: true, messages: [{ role: 'user', content: PII_PROMPT }] });
  assert.equal(mr.status, 200);
  assert.doesNotMatch(mr.body, PII_PLACEHOLDER);
  const me = events(mr.body).filter((e) => e.type === 'content_block_delta');
  assert.equal(me.filter((e) => e.delta.type === 'text_delta').map((e) => e.delta.text).join(''), `You said: ${PII_PROMPT}`);
  assert.deepEqual(JSON.parse(me.filter((e) => e.delta.type === 'input_json_delta').map((e) => e.delta.partial_json).join('')),
    { to: 'jane.roe@example.com', name: 'Jane Roe' });
  for (const seen of s.hp.seen) assert.doesNotMatch(seen.raw.toString('utf8'), PII_SURFACE);
});

test('pii gate: an authorize refusal comes back as is, before any detector call', async () => {
  const s = await piiSetup({ authorizeStatus: 402 });
  const r = await s.post('/v1/responses', { model: 'openai/gpt-5', pii_redaction: true, input: PII_PROMPT });
  assert.equal(r.status, 402);
  assert.equal(s.authorizes.length, 1);
  assert.equal(s.detector.calls.length, 0);
  assert.equal(s.hp.seen.length, 0);
  assert.equal(s.pt.inflight(), 0);
});

test('pii gate: without x-request-id the enclave mints one and uses it for authorize, the MAC and the forward', async () => {
  const s = await piiSetup();
  const r = await s.post('/v1/messages', { model: 'claude-x', pii_redaction: true, messages: [{ role: 'user', content: PII_PROMPT }] });
  assert.equal(r.status, 200);
  const id = s.hp.seen[0].headers['x-request-id'];
  assert.match(id, /^[0-9a-f-]{36}$/);
  assert.equal(s.authorizes[0].meta.requestId, id);
  assert.equal(s.hp.seen[0].headers['x-ppq-pii-calls-mac'], expectedMac(1, id));
});

test('pii gate: a detector failure is a 503 and horse-power is not reached', async () => {
  const s = await piiSetup();
  s.detector.mode = 'fail';
  const r = await s.post('/v1/responses', { model: 'openai/gpt-5', pii_redaction: true, input: PII_PROMPT });
  assert.equal(r.status, 503);
  assert.equal(JSON.parse(r.body).error.code, 'pii_redaction_unavailable');
  assert.equal(s.hp.seen.length, 0);
  assert.equal(s.pt.inflight(), 0);
});

test('pii gate: without a settle secret the count cannot be signed, so nothing is sent', async () => {
  const s = await piiSetup({ secret: '' });
  const r = await s.post('/v1/responses', { model: 'openai/gpt-5', pii_redaction: true, input: PII_PROMPT });
  assert.equal(r.status, 503);
  assert.equal(s.hp.seen.length, 0);
});

test('pii gate: a body over the cap is piped as before (horse-power is the backstop)', async () => {
  const s = await piiSetup({ bufferCap: 64 });
  const raw = JSON.stringify({ model: 'openai/gpt-5', pii_redaction: true, input: `${PII_PROMPT} ${'x'.repeat(200)}` });
  const r = await s.post('/v1/responses', raw);
  assert.equal(r.status, 200);
  assert.ok(s.hp.seen[0].raw.equals(Buffer.from(raw)), 'the original bytes, whole');
  assert.equal(s.detector.calls.length, 0);
  assert.equal(s.pt.inflight(), 0);
});

test('forged x-ppq-pii-calls headers never reach horse-power on any proxied route', async () => {
  const hp = await fakeHp();
  const pt = createPassthrough({ host: 'h', port: hp.port, requestImpl: http.request });
  const front = await enclaveFront(pt);
  await request(front, { path: '/echo', headers: { 'x-ppq-pii-calls': '0', 'x-ppq-pii-calls-mac': 'forged' } });
  assert.equal(hp.seen[0].headers['x-ppq-pii-calls'], undefined);
  assert.equal(hp.seen[0].headers['x-ppq-pii-calls-mac'], undefined);
});
