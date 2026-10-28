// horse-power #1156: on the chat path an OpenAI candidate (api_style
// openai-responses) is built by buildOpenAIResponsesRequest at the server's
// call site — this drives that call site end to end (the builder tests take
// creditId/safetySecret directly; CodeRabbit on #386 asked for the server to
// be exercised): a chat request becomes a Responses request to
// api.openai.com/v1/responses with OUR safety_identifier, OpenAI's SSE comes
// back as chat chunks under the public slug, and hp is told to price the
// counts against the openai row.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
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

const UPSTREAM_ID = 'gpt-5.5';
const WIRE_ECHO = 'gpt-5.5-2026-04-23';
const SLUG = 'openai/gpt-5.5';
const SAFETY_SECRET = 'safety-test-secret';

function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, web_search: false, max_tokens_cap: 50,
        provider_directive: { order: ['openai'], ignore: ['amazon-bedrock'] },
        upstreams: [
          { provider: 'openai', api_style: 'openai-responses', host: 'api.openai.com', path: '/v1/responses', key_ref: 'openai',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: true, context_length: 1050000, tier: 'default' },
          { provider: 'openrouter', api_style: 'openai', host: 'openrouter.ai', path: '/api/v1/chat/completions', key_ref: 'openrouter', upstream_model: SLUG },
        ],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors };
}

const evt = (ev) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;
const OAI_FRAMES = [
  { type: 'response.created', response: { id: 'resp_1', model: WIRE_ECHO, status: 'in_progress', usage: null } },
  { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', content: [] } },
  { type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, delta: 'pong' },
  { type: 'response.output_item.done', output_index: 0, item: { type: 'message', id: 'msg_1' } },
  { type: 'response.completed', response: { id: 'resp_1', model: WIRE_ECHO, status: 'completed', usage: { input_tokens: 11, output_tokens: 16, total_tokens: 27, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 9 } } } },
];

function fakeOpenAI({ key, cert }) {
  let mode = 'ok';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/v1/responses') { res.writeHead(404); return res.end(); }
    if (body.stream !== true) {
      // The non-streaming answer: one Responses object (horse-power #1159).
      res.writeHead(200, { 'content-type': 'application/json' });
      if (mode === 'json_failed') {
        return res.end(JSON.stringify({ id: 'resp_1', object: 'response', model: WIRE_ECHO, status: 'failed', error: { code: 'server_error', message: 'The server had an error' }, output: [], usage: null }));
      }
      return res.end(JSON.stringify({ id: 'resp_1', object: 'response', model: WIRE_ECHO, status: 'completed', output: [{ type: 'reasoning', id: 'rs_1', summary: [] }, { type: 'message', id: 'msg_1', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'pong', annotations: [] }] }], usage: OAI_FRAMES.at(-1).response.usage }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const f of OAI_FRAMES) res.write(evt(f));
    res.end();
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(`data: ${JSON.stringify({ id: 'gen-1', model: SLUG, provider: 'OpenAI', choices: [{ index: 0, delta: { content: 'pong' }, finish_reason: 'stop' }], usage: { prompt_tokens: 11, completion_tokens: 2, cost: 0.0001 } })}\n\ndata: [DONE]\n\n`);
    res.end();
  });
  return { server, seen };
}

function post(port, path, body, headers = {}) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'x-api-key': 'ppq-test-key', 'x-query-source': 'api', ...headers },
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

const REQ = { model: SLUG, stream: true, max_tokens: 200, user: 'attacker-chosen', messages: [{ role: 'user', content: 'Reply with exactly: pong' }] };

async function run({ withSecret, payload = REQ, oaiMode = 'ok' }) {
  const dir = mkdtempSync(join(tmpdir(), 'chat-direct-openai-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.openai.com',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  const [inboundPort, hpPort, orPort, oaiPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const oai = fakeOpenAI(tls);
  oai.setMode(oaiMode);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(oai.server, oaiPort)]);
  const env = {
    ...process.env,
    ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
    TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
    SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
    OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
    OPENAI_PORT: String(oaiPort), OPENAI_API_KEY: 'openai-test-key',
    OPENROUTER_API_KEY: 'or-test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
    NODE_EXTRA_CA_CERTS: certPath,
  };
  if (withSecret) env.SAFETY_IDENTIFIER_SECRET = SAFETY_SECRET;
  else delete env.SAFETY_IDENTIFIER_SECRET;
  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });
  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);
    const res = await post(inboundPort, '/v1/chat/completions', payload, { 'x-request-id': 'req-chat' });
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-chat'), `the settle\n${logs}`);
    return { res, sent: oai.seen[0], or: or.seen, settle, errors: hp.errors, logs };
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, oai.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
}

test('/v1/chat/completions: an openai-responses candidate is served direct with OUR safety_identifier; chat chunks come back under the public slug', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const { res, sent, or, settle } = await run({ withSecret: true });
  assert.equal(res.status, 200, res.body);
  assert.equal(or.length, 0, 'OpenRouter was never asked');
  assert.ok(sent, 'the request reached api.openai.com/v1/responses');
  assert.equal(sent.path, '/v1/responses');
  assert.equal(sent.headers.authorization, 'Bearer openai-test-key');
  assert.equal(sent.body.model, UPSTREAM_ID);
  assert.equal(sent.body.store, false);
  assert.equal(sent.body.max_output_tokens, 50, 'hp’s cap landed');
  assert.equal(sent.body.safety_identifier, createHmac('sha256', SAFETY_SECRET).update('credit-under-test').digest('hex'), 'HMAC of the AUTHENTICATED credit id, keyed by the secret');
  assert.equal('user' in sent.body, false, 'the caller’s user is dropped');
  // The client sees chat chunks under the public slug; the dated echo stays on the settle.
  const frames = res.body.split('\n\n').filter((f) => f.startsWith('data: ') && f !== 'data: [DONE]').map((f) => JSON.parse(f.slice(6)));
  assert.ok(frames.length >= 2, res.body);
  assert.ok(frames.every((c) => c.object === 'chat.completion.chunk' && c.model === SLUG), res.body);
  assert.ok(frames.some((c) => c.choices?.[0]?.delta?.content === 'pong'));
  assert.equal(settle.provider, 'openai');
  assert.equal(settle.direct_provider, 'openai');
  assert.equal(settle.cost_source, 'catalog-tokens');
  assert.equal(settle.upstream_model, UPSTREAM_ID);
  assert.equal(settle.served_model, WIRE_ECHO);
  assert.equal(settle.input_tokens, 11);
  assert.equal(settle.output_tokens, 16);
});

test('/v1/chat/completions: without SAFETY_IDENTIFIER_SECRET no identifier is sent at all', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const { res, sent } = await run({ withSecret: false });
  assert.equal(res.status, 200, res.body);
  assert.ok(sent);
  assert.equal('safety_identifier' in sent.body, false);
  assert.equal('user' in sent.body, false);
});

test('/v1/chat/completions: a NON-streaming request is served direct too — one chat.completion under the public slug, the dated echo on the settle (horse-power #1159)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const { res, sent, or, settle } = await run({ withSecret: true, payload: { ...REQ, stream: false } });
  assert.equal(res.status, 200, res.body);
  assert.equal(or.length, 0, 'OpenRouter was never asked');
  assert.ok(sent, 'the request reached api.openai.com/v1/responses');
  assert.equal(sent.body.stream, false, 'the caller’s mode rides the wire');
  assert.equal(sent.headers.accept, 'application/json');
  assert.doesNotMatch(res.headers['content-type'], /text\/event-stream/);
  const body = JSON.parse(res.body);
  assert.equal(body.object, 'chat.completion');
  assert.equal(body.model, SLUG, 'the dated echo is hidden from the client');
  assert.deepEqual(body.choices, [{ index: 0, message: { role: 'assistant', content: 'pong' }, finish_reason: 'stop' }]);
  assert.equal(body.usage.prompt_tokens, 11);
  assert.equal(body.usage.completion_tokens, 16);
  assert.equal(settle.provider, 'openai');
  assert.equal(settle.route, 'direct');
  assert.equal(settle.served_model, WIRE_ECHO);
  assert.equal(settle.input_tokens, 11);
  assert.equal(settle.output_tokens, 16);
  assert.equal(settle.usage_source, 'upstream');
});

test('/v1/chat/completions: a NON-streaming answer that is a failed Responses object is the error envelope to the client and an upstream failure on the settle, never a clean 200 (CodeRabbit on #390)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const { res, or, settle, errors } = await run({ withSecret: true, payload: { ...REQ, stream: false }, oaiMode: 'json_failed' });
  assert.equal(res.status, 200, 'the status was already on the wire');
  assert.equal(or.length, 0, 'no silent OpenRouter retry of a served request');
  const body = JSON.parse(res.body);
  assert.equal(body.error?.code, 502);
  assert.match(body.error.message, /The server had an error/);
  assert.equal(body.choices, undefined);
  assert.equal(settle.provider, 'openai');
  assert.equal(settle.failure_code, 'upstream_error_status');
  assert.equal(settle.trace?.stream_end, 'upstream_error');
  assert.ok(settle.input_tokens > 0, 'the accepted prompt still bills (authorize-time input)');
  // The sink carries the client's id inside the trace, keyed by settle_id.
  const report = errors.find((e) => e.settle_id === settle.settle_id || e.trace?.client_request_id === 'req-chat');
  assert.ok(report, `an error report reached hp\n${JSON.stringify(errors)}`);
  assert.equal(report.code, 'stream_failed');
  assert.equal(report.provider, 'openai');
});
