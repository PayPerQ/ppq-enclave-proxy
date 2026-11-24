// Azure OpenAI deployments on ppq-foundry (provider `azure`, api_style
// openai-responses): hp lists OpenAI first-party, then Azure, then the
// OpenRouter terminal. This drives the server end to end on all three
// dialects: an OpenAI failure falls to Azure, which is reached through the
// Foundry tunnel on /openai/v1/responses with the foundry key, and the bare
// deployment-id echo is hidden behind the public slug.
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

const DEPLOYMENT = 'gpt-6.1-sol';
const SLUG = 'openai/gpt-6.1-sol';
const SAFETY_SECRET = 'safety-test-secret';
const AZURE_HOST = 'ppq-foundry.services.ai.azure.com';
const AZURE_PATH = '/openai/v1/responses';

function fakeHp({ key, cert }) {
  const settles = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      const row = { upstream_model: DEPLOYMENT, or_slug: SLUG, supports_tools: true, supports_image_input: true, context_length: 1050000, tier: 'default' };
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, web_search: false, max_tokens_cap: 50,
        provider_directive: { order: ['azure', 'openai'], allow_fallbacks: true },
        upstreams: [
          { provider: 'openai', api_style: 'openai-responses', host: 'api.openai.com', path: '/v1/responses', key_ref: 'openai', ...row },
          { provider: 'azure', api_style: 'openai-responses', host: AZURE_HOST, path: AZURE_PATH, key_ref: 'foundry', ...row },
          { provider: 'openrouter', api_style: 'openai', host: 'openrouter.ai', path: '/api/v1/chat/completions', key_ref: 'openrouter', upstream_model: SLUG },
        ],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles };
}

const evt = (ev) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;
const USAGE = { input_tokens: 11, output_tokens: 16, total_tokens: 27, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 9 } };
const AZURE_FRAMES = [
  { type: 'response.created', response: { id: 'resp_1', model: DEPLOYMENT, status: 'in_progress', usage: null } },
  { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', content: [] } },
  { type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, delta: 'pong' },
  { type: 'response.output_item.done', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'pong', annotations: [] }] } },
  { type: 'response.completed', response: { id: 'resp_1', model: DEPLOYMENT, status: 'completed', usage: USAGE } },
];

/** One fake upstream: `fail` answers 503 (OpenAI down), otherwise the Responses stream. */
function fakeResponsesUpstream({ key, cert }, { path, fail = false }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== path) { res.writeHead(404); return res.end(); }
    if (fail) { res.writeHead(503, { 'content-type': 'application/json' }); return res.end('{"error":{"message":"unavailable"}}'); }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const f of AZURE_FRAMES) res.write(evt(f));
    res.end();
  });
  return { server, seen };
}

function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, body });
    res.writeHead(500); res.end();
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

test('azure: OpenAI fails, Azure serves chat, /v1/responses and /v1/messages through the Foundry tunnel with the foundry key', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'azure-direct-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', `subjectAltName=DNS:localhost,DNS:api.openai.com,DNS:${AZURE_HOST}`,
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  const [inboundPort, hpPort, orPort, oaiPort, azPort] = await Promise.all([freePort(), freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const oai = fakeResponsesUpstream(tls, { path: '/v1/responses', fail: true });
  const az = fakeResponsesUpstream(tls, { path: AZURE_PATH });
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(oai.server, oaiPort), listen(az.server, azPort)]);
  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENAI_PORT: String(oaiPort), OPENAI_API_KEY: 'openai-test-key',
      FOUNDRY_PORT: String(azPort), FOUNDRY_API_KEY: 'foundry-test-key',
      OPENROUTER_API_KEY: 'or-test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      SAFETY_IDENTIFIER_SECRET: SAFETY_SECRET,
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });
  const ourId = createHmac('sha256', SAFETY_SECRET).update('credit-under-test').digest('hex');
  const assertAzureSent = (sent) => {
    assert.ok(sent, `the request reached ${AZURE_HOST}${AZURE_PATH}\n${logs}`);
    assert.equal(sent.path, AZURE_PATH);
    assert.equal(sent.headers.host, AZURE_HOST);
    assert.equal(sent.headers.authorization, 'Bearer foundry-test-key');
    assert.equal(sent.headers['x-session-affinity'], undefined, 'no Fireworks-dialect header');
    assert.equal(sent.body.model, DEPLOYMENT);
    assert.equal(sent.body.store, false);
    assert.equal(sent.body.safety_identifier, ourId);
    assert.equal('provider' in sent.body, false);
  };
  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // Chat completions.
    const chat = await post(inboundPort, '/v1/chat/completions', { model: SLUG, stream: true, max_tokens: 200, user: 'attacker-chosen', messages: [{ role: 'user', content: 'ping' }] }, { 'x-request-id': 'req-chat' });
    assert.equal(chat.status, 200, chat.body);
    assertAzureSent(az.seen.at(-1));
    assert.equal(oai.seen.length, 1, 'OpenAI was tried first');
    const frames = chat.body.split('\n\n').filter((f) => f.startsWith('data: ') && f !== 'data: [DONE]').map((f) => JSON.parse(f.slice(6)));
    assert.ok(frames.every((c) => c.model === SLUG), chat.body);
    assert.ok(frames.some((c) => c.choices?.[0]?.delta?.content === 'pong'), chat.body);
    const chatSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-chat'), `the chat settle\n${logs}`);
    assert.equal(chatSettle.provider, 'azure');
    assert.equal(chatSettle.route, 'direct');
    assert.equal(chatSettle.upstream_model, DEPLOYMENT);
    assert.equal(chatSettle.input_tokens, 11);
    assert.equal(chatSettle.output_tokens, 16);

    // /v1/responses pass-through.
    const resp = await post(inboundPort, '/v1/responses', { model: SLUG, stream: true, max_output_tokens: 200, input: 'ping', reasoning: { effort: 'low' } }, { 'x-request-id': 'req-responses' });
    assert.equal(resp.status, 200, resp.body);
    assertAzureSent(az.seen.at(-1));
    assert.ok(resp.body.includes(`"model":"${SLUG}"`), resp.body);
    assert.ok(!resp.body.includes(`"model":"${DEPLOYMENT}"`), 'the deployment id is hidden');
    const respSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-responses'), `the responses settle\n${logs}`);
    assert.equal(respSettle.provider, 'azure');
    assert.equal(respSettle.route, 'direct');

    // /v1/messages by translation.
    const msg = await post(inboundPort, '/v1/messages', { model: SLUG, stream: true, max_tokens: 200, messages: [{ role: 'user', content: 'ping' }] }, { 'x-request-id': 'req-messages', 'anthropic-version': '2023-06-01' });
    assert.equal(msg.status, 200, msg.body);
    assertAzureSent(az.seen.at(-1));
    assert.ok(msg.body.includes('event: message_start'), msg.body);
    assert.ok(msg.body.includes(`"model":"${SLUG}"`), msg.body);
    assert.ok(msg.body.includes('pong'), msg.body);
    const msgSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-messages'), `the messages settle\n${logs}`);
    assert.equal(msgSettle.provider, 'azure');
    assert.equal(msgSettle.route, 'direct');

    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, oai.server, az.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
