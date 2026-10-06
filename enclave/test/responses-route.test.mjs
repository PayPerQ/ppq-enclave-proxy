// The in-enclave /v1/responses route (#280), driven end to end: the real
// server against a fake horse-power and a fake OpenRouter that speaks the
// OpenAI Responses dialect. What is asserted is the contract: the frames a
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
const CREATED = { type: 'response.created', sequence_number: 0, response: { id: 'gen-1790000000-r1', object: 'response', model: 'openai/gpt-5.5', status: 'in_progress', usage: null } };
const DELTAS = [
  { type: 'response.output_item.added', output_index: 0, item: { type: 'message', role: 'assistant', content: [] } },
  { type: 'response.output_text.delta', output_index: 0, delta: 'OK' },
  { type: 'response.output_text.delta', output_index: 0, delta: ' then' },
  { type: 'response.output_text.done', output_index: 0, text: 'OK then' },
];
const END = [
  { type: 'response.completed', response: { id: 'gen-1790000000-r1', object: 'response', model: 'openai/gpt-5.5', status: 'completed', usage: { input_tokens: 12, output_tokens: 3, total_tokens: 15, input_tokens_details: { cached_tokens: 4 }, output_tokens_details: { reasoning_tokens: 1 }, cost: 0.00021 } } },
];

/** Fake OpenRouter `/api/v1/responses`: answers per the current mode and records what it was sent. */
function fakeUpstream({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/api/v1/responses') { res.writeHead(404); return res.end(); }
    if (mode === 'status429') {
      res.writeHead(429, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: 'Rate limited by OpenRouter', code: 429, metadata: { provider_name: 'OpenAI' } }, user_id: 'org_test00000000000000000000' }));
    }
    if (mode === 'json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'gen-1790000000-j1', object: 'response', model: 'openai/gpt-5.5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'OK' }] }], usage: { input_tokens: 12, output_tokens: 2, total_tokens: 14, cost: 0.00019 } }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(CREATED));
    for (const d of DELTAS) res.write(sse(d));
    if (mode === 'cut') return res.end();
    if (mode === 'failed') {
      res.write(sse({ type: 'response.failed', response: { id: 'gen-1790000000-r1', status: 'failed', error: { code: 'server_error', message: 'Overloaded' }, usage: { input_tokens: 12, output_tokens: 2 } } }));
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

const REQ = (extra = {}) => ({ model: 'openai/gpt-5.5', input: 'Say OK.', stream: true, ...extra });

test('/v1/responses is served in-enclave: verbatim frames, a settle hp can price, reports on failure', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'responses-route-'));
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
      SAFETY_IDENTIFIER_SECRET: 'safety-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. A streamed answer: frames verbatim, cap and safety identifier applied, settle priced from the stream.
    up.setMode('stream');
    const streamed = await post(inboundPort, '/v1/responses', REQ({ user: 'caller-chosen' }), { 'x-request-id': 'req-stream' });
    assert.equal(streamed.status, 200, streamed.body);
    assert.match(streamed.headers['content-type'], /text\/event-stream/);
    assert.equal(streamed.body, [CREATED, ...DELTAS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const sentUp = up.seen.find((s) => s.path === '/api/v1/responses');
    assert.equal(sentUp.body.max_output_tokens, 50, 'hp’s cap lands on max_output_tokens, set when the caller sent none');
    assert.match(sentUp.body.safety_identifier, /^[0-9a-f]{64}$/, 'the per-end-user identity, in the Responses spelling');
    assert.equal(sentUp.body.user, undefined, 'the caller’s user is not forwarded for an OpenAI model');
    assert.equal(sentUp.body.usage, undefined, 'no usage.include on this dialect');
    assert.equal(sentUp.headers.authorization, 'Bearer test-key');
    assert.equal(hp.authorizes.at(-1).endpoint, 'responses');
    assert.ok(hp.authorizes.at(-1).input_tokens_o200k > 0);
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stream'), `the stream settle\n${logs}`);
    assert.equal(settle.endpoint, 'responses');
    assert.equal(settle.cost_source, 'responses-usage');
    assert.equal(settle.model, 'openai/gpt-5.5');
    assert.equal(settle.served_model, 'openai/gpt-5.5');
    assert.equal(settle.generation_id, 'gen-1790000000-r1');
    assert.equal(settle.input_tokens, 12);
    assert.equal(settle.output_tokens, 3);
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.reasoning_tokens, 1);
    assert.equal(settle.total_cost_usd, 0.00021);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(settle.trace?.route?.chosen, 'openrouter');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-stream'), false);

    // 1b. A requested max_output_tokens above the cap is clamped; a non-OpenAI model keeps the caller's user.
    await post(inboundPort, '/v1/responses', REQ({ model: 'anthropic/claude-sonnet-4.6', max_output_tokens: 4000, user: 'caller-chosen' }), { 'x-request-id': 'req-clamp' });
    const clampSent = up.seen.filter((s) => s.path === '/api/v1/responses').at(-1);
    assert.equal(clampSent.body.max_output_tokens, 50);
    assert.equal(clampSent.body.user, 'caller-chosen');
    assert.equal(clampSent.body.safety_identifier, undefined);

    // 2. A JSON (non-streaming) answer: passed through whole, settle from its usage block.
    up.setMode('json');
    const json = await post(inboundPort, '/v1/responses', REQ({ stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    assert.equal(JSON.parse(json.body).output[0].content[0].text, 'OK');
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.output_tokens, 2);
    assert.equal(jsonSettle.total_cost_usd, 0.00019);
    assert.equal(jsonSettle.trace?.stream_end, 'clean');

    // 3. A refused request: the status passes through, the body is sanitized, nothing settles.
    up.setMode('status429');
    const refused = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-429' });
    assert.equal(refused.status, 429);
    assert.equal(refused.body.includes('org_'), false, `the OpenRouter organisation id must not reach the client: ${refused.body}`);
    assert.equal(/openrouter/i.test(refused.body), false, `the upstream must not be named: ${refused.body}`);
    const report429 = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-429'), `the 429 report\n${logs}`);
    assert.equal(report429.code, 'upstream_error_status');
    assert.equal(report429.terminal, true);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-429'), false);

    // 4. A stream cut before response.completed: told in-band in the dialect, settled from the delivered deltas.
    up.setMode('cut');
    const cut = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-cut' });
    assert.equal(cut.status, 200);
    assert.ok(cut.body.endsWith('event: error\ndata: {"type":"error","code":"upstream_error","message":"upstream error"}\n\n'), `a named error event closes a truncated stream: ${cut.body.slice(-200)}`);
    const cutSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-cut'), `the cut settle\n${logs}`);
    assert.equal(cutSettle.failure_code, 'stream_failed');
    assert.equal(cutSettle.trace?.stream_end, 'upstream_error');
    assert.equal(cutSettle.usage_source, 'counted');
    assert.ok(cutSettle.output_tokens >= 1 && cutSettle.output_tokens <= 4, `counted "OK then": ${cutSettle.output_tokens}`);
    assert.ok(cutSettle.input_tokens > 0, 'the authorize-time measure stands in for the input');

    // 5. The upstream's own response.failed: relayed as sent, settled as an upstream error, no second frame.
    up.setMode('failed');
    const failed = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-failed' });
    assert.equal(failed.status, 200);
    assert.ok(failed.body.includes('"response.failed"'));
    assert.equal((failed.body.match(/event: error/g) || []).length, 0);
    const failedSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-failed'), `the failed settle\n${logs}`);
    assert.equal(failedSettle.failure_code, 'upstream_error_status');
    assert.equal(failedSettle.input_tokens, 12, 'the failed event’s usage is still read');

    // 6. The relay's own refusals, in the OpenAI shape, on both spellings of the path.
    const bad = await post(inboundPort, '/responses', { model: 'openai/gpt-5.5' });
    assert.equal(bad.status, 400);
    assert.deepEqual(JSON.parse(bad.body), { error: { message: 'input: Field required (a string or an array of input items)', type: 'invalid_request_error', code: 400 } });
    const noCred = await post(inboundPort, '/v1/responses', REQ(), { 'x-api-key': '' });
    assert.equal(noCred.status, 401);
    assert.equal(JSON.parse(noCred.body).error.type, 'authentication_error');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
