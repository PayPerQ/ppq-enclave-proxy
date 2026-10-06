// The in-enclave /v1/messages route (#275), driven end to end: the real
// server against a fake horse-power and a fake OpenRouter that speaks the
// Anthropic Messages dialect. What is asserted is the contract: the frames a
// client receives are the upstream's own, what hp is told at settle, and
// what is reported when the answer was not a clean one.
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

/** Fake horse-power: authorizes everything, names an Anthropic direct candidate, records the rest. */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  const authorizes = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      authorizes.push(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, max_tokens_cap: 50,
        upstreams: [{ provider: 'anthropic', api_style: 'anthropic', host: 'localhost', upstream_model: 'claude-sonnet-4-6-20260301' }],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, authorizes };
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const START = { type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model: 'anthropic/claude-sonnet-4.6', stop_reason: null, usage: { input_tokens: 12, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } } };
const DELTAS = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ' then' } },
  { type: 'content_block_stop', index: 0 },
];
const END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];

/**
 * Fake OpenRouter `/api/v1/messages` (and, on the same port, Anthropic's
 * count_tokens): answers per the current mode and records what it was sent.
 */
function fakeUpstream({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url === '/v1/messages/count_tokens') {
      if (req.headers['x-api-key'] !== 'anthropic-test-key') { res.writeHead(401); return res.end('{}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ input_tokens: 42 }));
    }
    if (req.url !== '/api/v1/messages') { res.writeHead(404); return res.end(); }
    if (mode === 'status429') {
      res.writeHead(429, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Rate limited by OpenRouter', metadata: { provider_name: 'Anthropic' } }, user_id: 'org_test00000000000000000000' }));
    }
    if (mode === 'json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'gen-1790000000-j1', type: 'message', role: 'assistant', model: 'anthropic/claude-sonnet-4.6', content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', usage: { input_tokens: 12, output_tokens: 2, cost: 0.00019 } }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(START));
    for (const d of DELTAS) res.write(sse(d));
    if (mode === 'cut') return res.end();
    if (mode === 'error-event') {
      res.write(sse({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }));
      return res.end();
    }
    for (const e of END) res.write(sse(e));
    res.end();
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

function post(port, path, body, headers = {}) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-api-key': 'ppq-test-key', 'x-query-source': 'api', ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.end(payload);
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

const REQ = (_requestId, extra = {}) => ({ model: 'anthropic/claude-sonnet-4.6', max_tokens: 200, stream: true, messages: [{ role: 'user', content: 'Say OK.' }], ...extra });

test('/v1/messages is served in-enclave: verbatim frames, a settle hp can price, reports on failure', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-route-'));
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
      // count_tokens goes to "Anthropic" on the same fake, under its own host override.
      ANTHROPIC_HOST: 'localhost', ANTHROPIC_PORT: String(upPort), ANTHROPIC_API_KEY: 'anthropic-test-key',
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

    // 1. A streamed answer: frames verbatim, max_tokens capped, settle priced from the stream.
    up.setMode('stream');
    const streamed = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-stream', 'anthropic-version': '2023-06-01' });
    assert.equal(streamed.status, 200, streamed.body);
    assert.match(streamed.headers['content-type'], /text\/event-stream/);
    assert.equal(streamed.body, [START, ...DELTAS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const sentUp = up.seen.find((s) => s.path === '/api/v1/messages');
    assert.equal(sentUp.body.max_tokens, 50, 'hp’s max_tokens_cap lands on the field the API requires');
    assert.equal(sentUp.body.stream, true);
    assert.equal(sentUp.headers['anthropic-version'], '2023-06-01', 'the dialect’s version header rides through');
    assert.equal(sentUp.headers.authorization, 'Bearer test-key', 'the enclave’s key, never the caller’s');
    assert.equal(hp.authorizes.at(-1).endpoint, 'messages');
    assert.ok(hp.authorizes.at(-1).input_tokens_o200k > 0, 'authorize carried the o200k measure');
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stream'), `the stream settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.cost_source, 'messages-usage');
    assert.equal(settle.model, 'anthropic/claude-sonnet-4.6');
    assert.equal(settle.served_model, 'anthropic/claude-sonnet-4.6');
    assert.equal(settle.generation_id, 'gen-1790000000-m1');
    assert.equal(settle.input_tokens, 12);
    assert.equal(settle.output_tokens, 3, 'message_delta’s cumulative count wins over message_start’s 1');
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.total_cost_usd, 0.00021);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(settle.trace?.route?.chosen, 'openrouter');
    assert.equal(settle.failure_code, undefined);
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-stream'), false, 'a clean answer reports nothing');

    // 2. A JSON (non-streaming) answer: passed through whole, settle from its usage block.
    up.setMode('json');
    const json = await post(inboundPort, '/v1/messages', REQ(null, { stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    assert.equal(JSON.parse(json.body).content[0].text, 'OK');
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.output_tokens, 2);
    assert.equal(jsonSettle.total_cost_usd, 0.00019);
    assert.equal(jsonSettle.generation_id, 'gen-1790000000-j1');
    assert.equal(jsonSettle.trace?.stream_end, 'clean');

    // 3. A refused request: the status passes through, the body is sanitized, nothing settles.
    up.setMode('status429');
    const refused = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-429' });
    assert.equal(refused.status, 429);
    assert.equal(refused.body.includes('org_'), false, `the OpenRouter organisation id must not reach the client: ${refused.body}`);
    assert.equal(/openrouter/i.test(refused.body), false, `the upstream must not be named: ${refused.body}`);
    assert.equal(JSON.parse(refused.body).type, 'error', 'still the dialect’s error shape');
    const report429 = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-429'), `the 429 report\n${logs}`);
    assert.equal(report429.code, 'upstream_error_status');
    assert.equal(report429.upstream_status, 429);
    assert.equal(report429.terminal, true);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-429'), false, 'a refused request never settles');

    // 4. A stream cut before message_stop: the client is told in-band, the settle bills what went out.
    up.setMode('cut');
    const cut = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-cut' });
    assert.equal(cut.status, 200);
    assert.ok(cut.body.endsWith('event: error\ndata: {"type":"error","error":{"type":"api_error","message":"upstream error"}}\n\n'), `an in-band error frame closes a truncated stream: ${cut.body.slice(-200)}`);
    const cutSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-cut'), `the cut settle\n${logs}`);
    assert.equal(cutSettle.failure_code, 'stream_failed');
    assert.equal(cutSettle.trace?.stream_end, 'upstream_error');
    assert.equal(cutSettle.usage_source, 'counted', 'no message_delta came: the delivered deltas are counted');
    assert.ok(cutSettle.output_tokens >= 1 && cutSettle.output_tokens <= 4, `counted "OK then": ${cutSettle.output_tokens}`);
    assert.equal(cutSettle.input_tokens, 12, 'message_start’s input count is kept');
    const cutReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-cut'), `the cut report\n${logs}`);
    assert.equal(cutReport.code, 'stream_failed');
    assert.equal(cutReport.terminal, false);

    // 5. The upstream's own in-band error event: relayed verbatim, settled as an upstream error.
    up.setMode('error-event');
    const errored = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-errev' });
    assert.equal(errored.status, 200);
    assert.ok(errored.body.includes('"overloaded_error"'), 'the upstream’s error event reaches the client as sent');
    assert.equal((errored.body.match(/event: error/g) || []).length, 0, 'no second frame is appended after the upstream’s own');
    const errSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-errev'), `the error-event settle\n${logs}`);
    assert.equal(errSettle.failure_code, 'upstream_error_status');
    assert.equal(errSettle.trace?.stream_end, 'upstream_error');

    // 6. The handler's own refusals are in the dialect.
    const bad = await post(inboundPort, '/v1/messages', { model: 'anthropic/claude-sonnet-4.6', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(bad.status, 400);
    assert.deepEqual(JSON.parse(bad.body), { type: 'error', error: { type: 'invalid_request_error', message: 'max_tokens: max_tokens: Field required (a positive integer)' } });
    const noCred = await post(inboundPort, '/v1/messages', REQ(), { 'x-api-key': '' });
    assert.equal(noCred.status, 401);
    assert.equal(JSON.parse(noCred.body).error.type, 'authentication_error');

    // 7. count_tokens: the enclave's own Anthropic key, only the count-bearing fields, the first-party id, nothing settled.
    const counted = await post(inboundPort, '/v1/messages/count_tokens', { model: 'anthropic/claude-sonnet-4.6', max_tokens: 10, stream: true, metadata: { user_id: 'u' }, messages: [{ role: 'user', content: 'hi' }], tools: [{ name: 't', input_schema: { type: 'object' } }] }, { 'x-request-id': 'req-count' });
    assert.equal(counted.status, 200, counted.body);
    assert.deepEqual(JSON.parse(counted.body), { input_tokens: 42 });
    const countSent = up.seen.find((s) => s.path === '/v1/messages/count_tokens');
    assert.deepEqual(Object.keys(countSent.body).sort(), ['messages', 'model', 'tools']);
    assert.equal(countSent.body.model, 'claude-sonnet-4-6-20260301', 'pinned to hp’s first-party id');
    assert.equal(countSent.headers['x-api-key'], 'anthropic-test-key');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-count'), false, 'count_tokens never settles');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
