// What hp RECEIVES about a failed request: every failure report carries the
// request's own `settle_id` and a `terminal` flag that is true only when the
// report is the request's FINAL failure — no further candidate is tried and
// nothing settles for it. A request that fails and still settles is described
// by its settle instead, so its reports must say `terminal: false`.
//
// The flag follows the BRANCH, not the code: `stream_failed` is final when the
// upstream answer could not be opened and not final when a stream broke after
// bytes went out (that one settles). So each case below drives a real branch
// of the real server, against a fake hp and fake upstreams, and asserts the
// report body hp would get.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CREDIT = '00000000-0000-4000-8000-000000000001';
const API_KEY_ID = 'key-under-test';
const TINFOIL_HOST = 'inference.tinfoil.sh';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
const SKIP = !haveOpenssl() && 'openssl not available';

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
function listen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
}
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
async function readJson(req) {
  try { return JSON.parse((await readBody(req)).toString('utf8') || '{}'); } catch { return {}; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Fake hp: /authorize answers by the requested model, so each case picks its
 * branch by name. Settles and error reports are recorded as received.
 */
function fakeHp(tls) {
  const settles = [];
  const errors = [];
  const authorizes = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      authorizes.push({ headers: req.headers, body });
      const m = body.model;
      if (m === 'test/reject') {
        res.writeHead(402, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ authorized: false, error: 'insufficient balance' }));
      }
      const answer = {
        authorized: true, credit_id: CREDIT, api_key_id: API_KEY_ID,
        resolved_model: m, is_free: false, upstreams: [],
      };
      if (m === 'private/attest') answer.upstreams = [{ provider: 'tinfoil', host: TINFOIL_HOST, key_ref: 'tinfoil' }];
      if (m === 'test/misrouted') answer.upstreams = [{ provider: 'tinfoil', host: TINFOIL_HOST, key_ref: 'tinfoil' }];
      // A malformed candidate list: the handler throws after authorize.
      if (m === 'test/throw') answer.upstreams = [null];
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(answer));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, authorizes };
}

const SSE_CHUNK = 'data: {"id":"gen-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"partial"}}]}\n\n';

/** Fake OpenRouter (chat + decisions): behaviour chosen by the model in the body. */
function fakeOpenRouter(tls) {
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    const m = body.model;
    if (req.url === '/api/alpha/decisions') {
      if (m === 'd/down') return req.socket.destroy();
      if (m === 'd/500') {
        res.writeHead(500, { 'content-type': 'application/json' });
        return res.end('{"error":{"message":"boom"}}');
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      if (m === 'd/nousage') return res.end('{"id":"gen-d","answers":{}}');
      return res.end(JSON.stringify({ id: 'gen-d', answers: {}, usage: { prompt_tokens: 3, completion_tokens: 1, cost: 0.0001 } }));
    }
    if (m === 'test/or-down') return req.socket.destroy();
    if (m === 'test/404') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end('{"error":{"message":"no such model","code":404}}');
    }
    if (m === 'test/503') {
      res.writeHead(503, { 'content-type': 'application/json' });
      return res.end('{"error":{"message":"overloaded","code":503}}');
    }
    if (m === 'test/midstream') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(SSE_CHUNK);
      return setTimeout(() => req.socket.destroy(), 50);
    }
    if (m === 'test/slow') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(SSE_CHUNK);
      const t = setInterval(() => res.write(SSE_CHUNK), 100);
      res.on('close', () => clearInterval(t));
      return undefined;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({
      id: 'gen-1', object: 'chat.completion', model: m,
      choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    }));
  });
  return { server };
}

/** Fake Tinfoil router for the sealed relay: the current case sets `mode`. */
function fakeTinfoil(tls) {
  const state = { mode: 'ok' };
  const server = https.createServer(tls, async (req, res) => {
    await readBody(req);
    const usage = 'prompt=3,completion=1,total=4,model=kimi-k3';
    if (state.mode === 'down') return req.socket.destroy();
    if (state.mode === '500') {
      res.writeHead(500, { 'content-type': 'application/json' });
      return res.end('{"error":"router error"}');
    }
    if (state.mode === '500-cut' || state.mode === '500-slow') {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.write('{"error":"router');
      if (state.mode === '500-cut') setTimeout(() => req.socket.destroy(), 50);
      return; // 500-slow: left open until the client goes away
    }
    if (state.mode === '302') {
      res.writeHead(302, { location: 'https://elsewhere.invalid/' });
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'application/json', 'x-tinfoil-usage-metrics': usage, 'ehbp-response-nonce': 'ab' });
    if (state.mode === 'midstream') {
      res.write('opaque-sealed-bytes');
      return setTimeout(() => req.socket.destroy(), 50);
    }
    return res.end('opaque-sealed-bytes');
  });
  return { server, state };
}

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'report-context-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', `subjectAltName=DNS:localhost,DNS:${TINFOIL_HOST}`,
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, tinfoilPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const tinfoil = fakeTinfoil(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(tinfoil.server, tinfoilPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      TINFOIL_PORT: String(tinfoilPort), TINFOIL_API_KEY: 'test-tinfoil-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { text: '' };
  child.stdout.on('data', (d) => { logs.text += d; });
  child.stderr.on('data', (d) => { logs.text += d; });
  env = { dir, inboundPort, hp, or, tinfoil, child, logs };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of [env.hp.server, env.or.server, env.tinfoil.server]) s.closeAllConnections?.();
  await Promise.all([env.hp.server, env.or.server, env.tinfoil.server].map((s) => new Promise((r) => s.close(r))));
  rmSync(env.dir, { recursive: true, force: true });
});

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await sleep(25);
  }
  assert.fail(`timed out waiting for ${what}\n${env?.logs.text ?? ''}`);
}

let seq = 0;
const nextId = (tag) => `rc-${tag}-${++seq}`;

/** POST to the enclave. `abortAfterFirstChunk` hangs up once the body starts. */
function post(path, { headers = {}, body, abortAfterFirstChunk = false } = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-credit-id': CREDIT, 'x-query-source': 'api', ...headers,
      },
    }, (res) => {
      if (abortAfterFirstChunk) {
        res.once('data', () => { r.destroy(); resolve(res.statusCode); });
        return;
      }
      res.resume();
      res.on('end', () => resolve(res.statusCode));
      res.on('error', () => resolve(res.statusCode));
    });
    r.on('error', (e) => (abortAfterFirstChunk ? resolve(0) : reject(e)));
    r.end(payload);
  });
}

const chat = (id, model, extra = {}) =>
  post('/v1/chat/completions', {
    headers: { 'x-request-id': id },
    body: extra.raw ?? { model, stream: extra.stream ?? false, messages: [{ role: 'user', content: 'hi' }] },
    abortAfterFirstChunk: extra.abort,
  });
const decisions = (id, model) =>
  post('/v1/decisions', {
    headers: { 'x-request-id': id },
    body: { model, state: 's', questions: { q: { type: 'noul', instructions: 'i' } } },
  });
const relay = (id) =>
  post('/private/v1/chat/completions', {
    headers: { 'x-request-id': id, 'x-private-model': 'private/kimi-k3', 'ehbp-encapsulated-key': 'aa' },
    body: Buffer.from('sealed-ciphertext'),
  });

/**
 * Every report hp received for one request, once `count` have arrived, plus a
 * short grace so an unexpected extra one is seen too. Correlated through the
 * trace: the client's own x-request-id never rides the top-level request_id.
 */
async function reportsFor(id, count) {
  const mine = () => env.hp.errors.filter((e) => e.trace?.client_request_id === id);
  await waitFor(() => mine().length >= count, `${count} report(s) for ${id}`);
  await sleep(150);
  return mine();
}
const settleFor = (id) => waitFor(() => env.hp.settles.find((s) => s.request_id === id), `the settle for ${id}`);
async function noSettleFor(id) {
  await sleep(300);
  assert.equal(env.hp.settles.some((s) => s.request_id === id), false, `${id} must not settle`);
}

/** The single report for a request, with its settle correlation checked. */
async function onlyReport(id, code) {
  const reports = await reportsFor(id, 1);
  assert.deepEqual(reports.map((r) => r.code), [code]);
  assert.match(reports[0].settle_id, UUID_RE, 'every report carries the request settle_id');
  return reports[0];
}

// ── chat ───────────────────────────────────────────────────────────────────

test('chat: unreadable body is final, with no account attached', { skip: SKIP }, async () => {
  const id = nextId('unreadable');
  assert.equal(await chat(id, null, { raw: '{not json' }), 400);
  const r = await onlyReport(id, 'request_unreadable');
  assert.equal(r.terminal, true);
  assert.equal('credit_id' in r, false);
});

test('chat: a model that is not a string is final', { skip: SKIP }, async () => {
  const id = nextId('notstring');
  assert.equal(await chat(id, null, { raw: { model: 42, messages: [] } }), 400);
  assert.equal((await onlyReport(id, 'model_rejected_not_string')).terminal, true);
});

test('chat: an authorize refusal is final and names no account', { skip: SKIP }, async () => {
  const id = nextId('authreject');
  assert.equal(await chat(id, 'test/reject'), 402);
  const r = await onlyReport(id, 'authorize_rejected');
  assert.equal(r.terminal, true);
  assert.equal('credit_id' in r, false);
});

test('chat: a retired AutoClaw id is refused in measured code, final, and carries the account', { skip: SKIP }, async () => {
  const id = nextId('smart');
  assert.equal(await chat(id, 'autoclaw/test'), 400);
  const r = await onlyReport(id, 'model_rejected_smart_routing');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  assert.equal(r.api_key_id, API_KEY_ID);
});

test('chat: an unauthorized free alias is final', { skip: SKIP }, async () => {
  const id = nextId('free');
  assert.equal(await chat(id, 'openrouter/free'), 400);
  const r = await onlyReport(id, 'free_model_unauthorized');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  assert.equal(r.api_key_id, API_KEY_ID);
  await noSettleFor(id);
});

test('chat: a private model with no private candidate is final', { skip: SKIP }, async () => {
  const id = nextId('privpath');
  assert.equal(await chat(id, 'private/test'), 400);
  assert.equal((await onlyReport(id, 'model_rejected_private_path')).terminal, true);
});

test('chat: a public model routed to the private provider is final', { skip: SKIP }, async () => {
  const id = nextId('misrouted');
  assert.equal(await chat(id, 'test/misrouted'), 502);
  assert.equal((await onlyReport(id, 'upstream_unreachable')).terminal, true);
});

test('chat: an attestation failure is not final; the unreachable that follows is', { skip: SKIP }, async () => {
  const id = nextId('attest');
  assert.equal(await chat(id, 'private/attest'), 502);
  const reports = await reportsFor(id, 2);
  assert.deepEqual(
    reports.map((r) => [r.code, r.terminal]),
    [['tinfoil_attestation_failed', false], ['upstream_unreachable', true]],
  );
  assert.equal(reports[0].settle_id, reports[1].settle_id, 'both reports belong to one request');
  assert.equal(reports.filter((r) => r.terminal).length, 1, 'exactly one final report per request');
  await noSettleFor(id);
});

test('chat: the last candidate failing to connect is final', { skip: SKIP }, async () => {
  const id = nextId('ordown');
  assert.equal(await chat(id, 'test/or-down'), 502);
  const r = await onlyReport(id, 'upstream_unreachable');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  await noSettleFor(id);
});

test('chat: a passed-through upstream error status settles, so it is not final', { skip: SKIP }, async () => {
  const id = nextId('404');
  assert.equal(await chat(id, 'test/404'), 404);
  const r = await onlyReport(id, 'upstream_error_status');
  assert.equal(r.terminal, false);
  const settle = await settleFor(id);
  assert.equal(r.settle_id, settle.settle_id, 'the report and the settle name the same request');
  assert.equal(settle.failure_code, 'upstream_error_status', 'the settle says how it failed');
  assert.equal(settle.failure_status, 404, 'the settle carries the passed-through status');
});

test('chat: a passed-through upstream 503 settles with failure_status 503', { skip: SKIP }, async () => {
  const id = nextId('503');
  assert.equal(await chat(id, 'test/503'), 503);
  const r = await onlyReport(id, 'upstream_error_status');
  const settle = await settleFor(id);
  assert.equal(settle.failure_code, 'upstream_error_status');
  assert.equal(settle.failure_status, 503, 'the settle carries the status the client was answered with');
  assert.equal(Number.isInteger(settle.failure_status), true);
  assert.equal(r.upstream_status, settle.failure_status, 'the report and the settle agree about the status');
});

test('chat: a stream that breaks mid-answer settles, so it is not final', { skip: SKIP }, async () => {
  const id = nextId('midstream');
  await chat(id, 'test/midstream', { stream: true });
  const r = await onlyReport(id, 'stream_failed');
  assert.equal(r.terminal, false);
  const settle = await settleFor(id);
  assert.equal(r.settle_id, settle.settle_id);
  assert.equal(settle.failure_code, 'stream_failed', 'the settle says how it failed');
  assert.equal('failure_status' in settle, false, 'a failure with no upstream status carries none, not null');
});

test('chat: a client abort settles what was delivered, so it is not final', { skip: SKIP }, async () => {
  const id = nextId('abort');
  await chat(id, 'test/slow', { stream: true, abort: true });
  const r = await onlyReport(id, 'client_abort');
  assert.equal(r.terminal, false);
  const settle = await settleFor(id);
  assert.equal(r.settle_id, settle.settle_id);
  assert.equal('failure_code' in settle, false, 'a client leaving is not a failure of the request');
});

test('chat: a served request reports nothing', { skip: SKIP }, async () => {
  const id = nextId('ok');
  assert.equal(await chat(id, 'test/ok'), 200);
  const settle = await settleFor(id);
  assert.equal('failure_code' in settle, false, 'a served request settles with no failure_code');
  assert.equal('failure_status' in settle, false, 'nor a failure_status');
  await sleep(150);
  assert.equal(env.hp.errors.some((e) => e.trace?.client_request_id === id), false);
});

// ── decisions ──────────────────────────────────────────────────────────────

test('decisions: an unreachable upstream is final', { skip: SKIP }, async () => {
  const id = nextId('d-down');
  assert.equal(await decisions(id, 'd/down'), 502);
  const r = await onlyReport(id, 'upstream_unreachable');
  assert.equal(r.terminal, true);
  assert.equal(r.api_key_id, API_KEY_ID);
  await noSettleFor(id);
});

test('decisions: a refused request never settles, so its error status is final', { skip: SKIP }, async () => {
  const id = nextId('d-500');
  assert.equal(await decisions(id, 'd/500'), 500);
  assert.equal((await onlyReport(id, 'upstream_error_status')).terminal, true);
  await noSettleFor(id);
});

test('decisions: a served answer with no usage still settles, so it is not final', { skip: SKIP }, async () => {
  const id = nextId('d-nousage');
  assert.equal(await decisions(id, 'd/nousage'), 200);
  const r = await onlyReport(id, 'decisions_usage_missing');
  assert.equal(r.terminal, false);
  const settle = await settleFor(id);
  assert.equal(r.settle_id, settle.settle_id);
  assert.equal('failure_code' in settle, false, 'the answer was served');
});

test('decisions: a served answer settles with no failure_code and reports nothing', { skip: SKIP }, async () => {
  const id = nextId('d-ok');
  assert.equal(await decisions(id, 'd/ok'), 200);
  assert.equal('failure_code' in (await settleFor(id)), false);
  await sleep(150);
  assert.equal(env.hp.errors.some((e) => e.trace?.client_request_id === id), false);
});

// ── private relay ──────────────────────────────────────────────────────────

test('relay: an unreachable router is final', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = 'down';
  const id = nextId('r-down');
  assert.equal(await relay(id), 502);
  const r = await onlyReport(id, 'upstream_unreachable');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  await noSettleFor(id);
});

test('relay: a non-2xx answer never settles, so its error status is final', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = '500';
  const id = nextId('r-500');
  assert.equal(await relay(id), 500);
  assert.equal((await onlyReport(id, 'upstream_error_status')).terminal, true);
  await noSettleFor(id);
});

test('relay: a non-2xx body that breaks off still sends exactly one final report', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = '500-cut';
  const id = nextId('r-500-cut');
  await relay(id).catch(() => {});
  await sleep(400);
  const r = await onlyReport(id, 'upstream_error_status');
  assert.equal(r.terminal, true);
  assert.equal(r.upstream_status, 500);
  await noSettleFor(id);
});

test('relay: a client that leaves during a non-2xx body adds no second final report', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = '500-slow';
  const id = nextId('r-500-gone');
  await post('/private/v1/chat/completions', {
    headers: { 'x-request-id': id, 'x-private-model': 'private/kimi-k3', 'ehbp-encapsulated-key': 'aa' },
    body: Buffer.from('sealed-ciphertext'),
    abortAfterFirstChunk: true,
  });
  await sleep(400);
  const r = await onlyReport(id, 'upstream_error_status');
  assert.equal(r.terminal, true);
  assert.equal(r.upstream_status, 500);
  await noSettleFor(id);
});

test('relay: a 3xx answer never settles either, so it is reported as final too', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = '302';
  const id = nextId('r-302');
  assert.equal(await relay(id), 302);
  const r = await onlyReport(id, 'upstream_error_status');
  assert.equal(r.terminal, true);
  assert.equal(r.upstream_status, 302);
  await noSettleFor(id);
});

test('relay: a body that cannot be read after authorize is final and names the account', { skip: SKIP }, async () => {
  const id = nextId('r-unreadable');
  // Over the 25 MB read bound: the enclave drops the upload, so the client may
  // see a reset instead of the 400. The report is what this asserts.
  await post('/private/v1/chat/completions', {
    headers: { 'x-request-id': id, 'x-private-model': 'private/kimi-k3', 'ehbp-encapsulated-key': 'aa' },
    body: Buffer.alloc(26 * 1024 * 1024),
  }).catch(() => {});
  const r = await onlyReport(id, 'request_unreadable');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  await noSettleFor(id);
});

test('relay: a request without the encapsulated key is refused and not reported', { skip: SKIP }, async () => {
  const id = nextId('r-plain');
  assert.equal(await post('/private/v1/chat/completions', {
    headers: { 'x-request-id': id, 'x-private-model': 'private/kimi-k3' },
    body: Buffer.from('plaintext'),
  }), 400);
  await sleep(400);
  assert.deepEqual(env.hp.errors.filter((e) => e.trace?.client_request_id === id), []);
  await noSettleFor(id);
});

test('relay: a 2xx stream that breaks still settles, so it is not final', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = 'midstream';
  const id = nextId('r-mid');
  await relay(id);
  const r = await onlyReport(id, 'stream_failed');
  assert.equal(r.terminal, false);
  const settle = await settleFor(id);
  assert.equal(r.settle_id, settle.settle_id);
  assert.equal(settle.failure_code, 'stream_failed', 'the settle says how it failed');
  assert.equal('failure_status' in settle, false, 'a failure with no upstream status carries none, not null');
});

test('relay: a clean answer settles with no failure_code and reports nothing', { skip: SKIP }, async () => {
  env.tinfoil.state.mode = 'ok';
  const id = nextId('r-ok');
  assert.equal(await relay(id), 200);
  const settle = await settleFor(id);
  assert.equal('failure_code' in settle, false);
  assert.equal(settle.input_tokens, 3, 'priced from the usage line');
  await sleep(150);
  assert.equal(env.hp.errors.some((e) => e.trace?.client_request_id === id), false);
});

// ── a handler that throws ──────────────────────────────────────────────────

test('chat: a throw after authorize and before any settle is final and names the account', { skip: SKIP }, async () => {
  const id = nextId('throw');
  assert.equal(await chat(id, 'test/throw'), 500);
  const r = await onlyReport(id, 'internal_error');
  assert.equal(r.terminal, true);
  assert.equal(r.credit_id, CREDIT);
  assert.equal(r.api_key_id, API_KEY_ID);
  assert.equal(r.query_source, 'api');
  await noSettleFor(id);
});

// ── authorize correlation ──────────────────────────────────────────────────

test('authorize: hp receives the client x-request-id the settle also carries', { skip: SKIP }, async () => {
  const id = nextId('auth-id');
  const before = env.hp.authorizes.length;
  assert.equal(await chat(id, 'test/ok'), 200);
  const settle = await settleFor(id);
  const mine = env.hp.authorizes.slice(before).filter((a) => a.headers['x-request-id'] === id);
  assert.equal(mine.length, 1, 'the authorize call carries the request id');
  assert.equal(settle.request_id, mine[0].headers['x-request-id']);
});

test('authorize: without a client id, hp receives the enc- id the enclave minted', { skip: SKIP }, async () => {
  const before = env.hp.authorizes.length;
  assert.equal(await post('/v1/decisions', {
    body: { model: 'd/ok', state: 's', questions: { q: { type: 'noul', instructions: 'i' } } },
  }), 200);
  const auth = await waitFor(() => env.hp.authorizes.slice(before)[0], 'the authorize call');
  const sent = auth.headers['x-request-id'];
  assert.match(sent, /^enc-\d{10,}-[a-z0-9]{1,12}$/, 'a minted id, not one hp has to invent');
  const settle = await settleFor(sent);
  assert.equal(settle.request_id, sent, 'the authorize and the settle name the same request');
});
