// A client that hangs up is noticed whenever it happens, and the settle bills
// the prompt the provider consumed (Oct 17-19 security reports: Kickpy's late
// disconnect handler; Matt's "input unbilled before the first delta").
//
// Before: chatCompletion registered `res.on('close')` only once the upstream
// stream was wired up, after the awaits for the body, the input measure,
// authorize and the upstream connect. `close` is one-shot, so a client gone
// during authorize was never seen: the prompt still went to the provider, the
// generation ran to the end for nobody, and the customer was settled for it.
// And in settleNow the input fallback sat inside `if (counted.tokens > 0)`, so
// an abort after the upstream's headers but before its first delta settled
// input 0 for a prompt the provider had already billed PPQ for.
//
// Drives the real server against a fake hp and a fake OpenRouter (the shape of
// upstream-retry.test.mjs) and asserts what hp receives.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
function listen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
}
function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
  });
}

/**
 * Fake horse-power: authorizes everything after `authorizeDelayMs` (so a client
 * can hang up while authorize is in flight), records settles and reports.
 */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  const authorizes = [];
  const state = { authorizeDelayMs: 0 };
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      authorizes.push(body);
      await new Promise((r) => setTimeout(r, state.authorizeDelayMs));
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: [],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, authorizes, state };
}

/**
 * Fake OpenRouter. `hold`: answers 200 text/event-stream with a comment line
 * and then keeps the stream open (the prefill is running, no delta yet) until
 * the enclave cancels it; records that cancellation. `json404`: a refused
 * request. Anything else: a complete one-shot JSON answer.
 */
function fakeUpstream({ key, cert }) {
  const state = { mode: 'json', asked: 0, cancelled: 0, seen: [] };
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    state.asked += 1;
    state.seen.push({ path: req.url, body });
    if (state.mode === 'hold') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(': prefill\n\n');
      req.socket.on('close', () => { state.cancelled += 1; });
      return; // held open until the enclave destroys the socket
    }
    if (state.mode === 'json404') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: 'No endpoints found', code: 404 } }));
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
      choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    }));
  });
  return { server, state };
}

const CHAT_BODY = JSON.stringify({
  model: 'openai/gpt-4.1-mini', stream: true,
  messages: [{ role: 'user', content: 'Write a long essay about the history of the enclave proxy and why it bills input.' }],
});
const MESSAGES_BODY = JSON.stringify({
  model: 'anthropic/claude-sonnet-4.6', max_tokens: 200, stream: true,
  messages: [{ role: 'user', content: 'Write a long essay about the history of the enclave proxy and why it bills input.' }],
});

/** Send a request; `onHeaders` gets the response once its headers arrive. */
function start(port, path, body, requestId, onHeaders = () => {}) {
  const r = https.request({
    host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false,
    headers: {
      'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
      'x-credit-id': '00000000-0000-4000-8000-000000000001',
      'x-query-source': 'api', 'x-request-id': requestId,
    },
  }, onHeaders);
  r.on('error', () => {}); // our own destroy
  r.end(body);
  return r;
}

/** Send a request and resolve once the response headers arrive. */
function open(port, path, body, requestId) {
  return new Promise((resolve) => {
    const req = start(port, path, body, requestId, (res) => resolve({ req, res }));
  });
}

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.fail(`timed out waiting for ${what}`);
}

test('a client that hangs up is noticed at any point, and the consumed prompt is billed', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'client-abort-billing-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, upPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair);
  const up = fakeUpstream(tlsPair);
  await Promise.all([listen(hp.server, hpPort), listen(up.server, upPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(upPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. Gone DURING AUTHORIZE: the prompt never reaches the provider, nothing
    //    settles, one terminal client_abort report is the request's trace.
    hp.state.authorizeDelayMs = 700;
    up.state.mode = 'json';
    up.state.asked = 0;
    const early = start(inboundPort, '/v1/chat/completions', CHAT_BODY, 'req-gone-during-authorize');
    await waitFor(() => hp.authorizes.length === 1, `authorize to be in flight\n${logs}`);
    early.destroy();
    const abandoned = await waitFor(
      () => hp.errors.find((e) => e.trace?.client_request_id === 'req-gone-during-authorize'),
      `the client_abort report\n${logs}`,
    );
    assert.equal(abandoned.code, 'client_abort');
    assert.equal(abandoned.terminal, true, 'final: nothing follows this report');
    assert.equal(abandoned.trace?.stream_end, 'client_abort');
    assert.equal(abandoned.credit_id, 'credit-under-test', 'reported against the billed account');
    await new Promise((r) => setTimeout(r, 400)); // past where the upstream send would have happened
    assert.equal(up.state.asked, 0, 'the prompt was never sent to the provider');
    assert.equal(hp.settles.some((s) => s.request_id === 'req-gone-during-authorize'), false, 'nothing was served, nothing settles');
    assert.match(logs, /request abandoned before upstream: client gone/);

    // 2. Gone AFTER THE UPSTREAM'S HEADERS, BEFORE THE FIRST DELTA: the upstream
    //    is cancelled at once, and the settle bills the prompt (from the
    //    authorize-time o200k measure, marked as counted) with output 0.
    hp.state.authorizeDelayMs = 0;
    up.state.mode = 'hold';
    up.state.asked = 0;
    up.state.cancelled = 0;
    const { req: mid, res: midRes } = await open(inboundPort, '/v1/chat/completions', CHAT_BODY, 'req-gone-before-first-delta');
    assert.ok(midRes, 'the enclave relayed the upstream headers');
    assert.equal(midRes.statusCode, 200);
    midRes.on('data', () => {});
    mid.destroy();
    await waitFor(() => up.state.cancelled === 1, `the upstream to be cancelled\n${logs}`);
    const midSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-gone-before-first-delta'), `the abort settle\n${logs}`);
    assert.equal(midSettle.trace?.stream_end, 'client_abort');
    assert.equal(midSettle.output_tokens, 0, 'no delta went out');
    assert.ok(midSettle.input_tokens_o200k > 10, `the measure is on the row: ${midSettle.input_tokens_o200k}`);
    assert.equal(midSettle.input_tokens, midSettle.input_tokens_o200k, 'the consumed prompt is billed from the measure');
    assert.equal(midSettle.usage_source, 'counted', 'an estimate, and says so');
    const midReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-gone-before-first-delta'), `the abort report\n${logs}`);
    assert.equal(midReport.code, 'client_abort');
    assert.equal(midReport.terminal, false, 'not final: the settle above followed');
    assert.equal(hp.errors.filter((e) => e.trace?.client_request_id === 'req-gone-before-first-delta').length, 1, 'one report, not a stream_failed twin');

    // 3. Control: a refused request (upstream 404, passed through) still
    //    settles 0/0 -- the input fallback is for served answers only.
    up.state.mode = 'json404';
    const refused = await new Promise((resolve, reject) => {
      const r = https.request({
        host: '127.0.0.1', port: inboundPort, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
        headers: {
          'content-type': 'application/json', 'content-length': Buffer.byteLength(CHAT_BODY),
          'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api', 'x-request-id': 'req-refused-404',
        },
      }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      r.on('error', reject);
      r.end(CHAT_BODY);
    });
    assert.equal(refused, 404);
    const refusedSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-refused-404'), `the 404 settle\n${logs}`);
    assert.equal(refusedSettle.input_tokens, 0, 'a refused request bills no input');
    assert.equal(refusedSettle.output_tokens, 0);

    // 4. Control: a complete answer still settles from its usage frame.
    up.state.mode = 'json';
    const ok = await new Promise((resolve, reject) => {
      const body = JSON.stringify({ model: 'openai/gpt-4.1-mini', stream: false, messages: [{ role: 'user', content: 'hi' }] });
      const r = https.request({
        host: '127.0.0.1', port: inboundPort, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
        headers: {
          'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
          'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api', 'x-request-id': 'req-complete',
        },
      }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      r.on('error', reject);
      r.end(body);
    });
    assert.equal(ok, 200);
    const okSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-complete'), `the complete settle\n${logs}`);
    assert.equal(okSettle.usage_source, 'upstream');
    assert.equal(okSettle.input_tokens, 3);
    assert.equal(okSettle.output_tokens, 1);
    assert.equal(okSettle.trace?.stream_end, 'clean');

    // 5. The dialect relay has the same settle shape: /v1/messages, gone
    //    after the upstream's headers and before message_start, bills the
    //    prompt from its own measure.
    up.state.mode = 'hold';
    up.state.cancelled = 0;
    const { req: dm, res: dmRes } = await open(inboundPort, '/v1/messages', MESSAGES_BODY, 'req-messages-gone-early');
    assert.ok(dmRes, 'the relay forwarded the upstream headers');
    assert.equal(dmRes.statusCode, 200);
    dmRes.on('data', () => {});
    dm.destroy();
    await waitFor(() => up.state.cancelled === 1, `the dialect upstream to be cancelled\n${logs}`);
    const dmSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-messages-gone-early'), `the dialect abort settle\n${logs}`);
    assert.equal(dmSettle.endpoint, 'messages');
    assert.equal(dmSettle.trace?.stream_end, 'client_abort');
    assert.equal(dmSettle.output_tokens, 0);
    assert.ok(dmSettle.input_tokens_o200k > 10, `the measure is on the row: ${dmSettle.input_tokens_o200k}`);
    assert.equal(dmSettle.input_tokens, dmSettle.input_tokens_o200k, 'the consumed prompt is billed from the measure');
    assert.equal(dmSettle.usage_source, 'counted');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
