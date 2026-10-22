// The `:online` suffix on the enclave path (horse-power #1055). hp peels the
// suffix off `resolved_model` with every other routing suffix and answers
// /authorize with `web_search: true` instead; the enclave must turn that into
// the search transport each dialect's upstream actually runs, and record the
// request as online. Before this, the suffix was simply lost: no search, no
// error, `isOnline: false`.
//
// Drives the real server against a fake backend and a fake OpenRouter that
// records every body it is sent, like trace-marks.test.mjs.
import { test, before, after } from 'node:test';
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
const SKIP = !haveOpenssl() && 'openssl not available';

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
 * Fake hp: resolves `:online` the way resolveEnclaveModel does (suffix off the
 * model, `web_search: true`), except for `legacy/*`, which plays an hp build
 * that predates the directive and sends no `web_search` at all.
 */
function fakeHp(tls) {
  const settles = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      const m = String(body.model);
      const online = m.endsWith(':online');
      const answer = {
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: online ? m.slice(0, -':online'.length) : m, is_free: false, upstreams: [],
      };
      if (online && !m.startsWith('legacy/')) answer.web_search = true;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(answer));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles };
}

/** Fake OpenRouter: records each body, answers a minimal JSON body in the path's dialect. */
function fakeOpenRouter(tls) {
  const seen = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    // The enclave forwards no request id upstream, so the test plants one in
    // the prompt text and pairs each recorded body with its own request.
    seen.push({ path: req.url, body, requestId: JSON.stringify(body).match(/online-\d+/)?.[0] });
    res.writeHead(200, { 'content-type': 'application/json' });
    // A `byok/*` model plays a BYOK generation: OpenRouter reports is_byok and
    // the provider's inference cost beside a `cost` the extractors discard.
    const cost = String(body.model).startsWith('byok/')
      ? { is_byok: true, cost: 0.0009, cost_details: { upstream_inference_cost: 0.0001 } }
      : { cost: 0.0001 };
    if (req.url === '/api/v1/responses') {
      return res.end(JSON.stringify({ id: 'gen-r', object: 'response', model: body.model, status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'OK' }] }], usage: { input_tokens: 3, output_tokens: 1, total_tokens: 4, ...cost } }));
    }
    if (req.url === '/api/v1/messages') {
      return res.end(JSON.stringify({ id: 'gen-m', type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', usage: { input_tokens: 3, output_tokens: 1, ...cost } }));
    }
    return res.end(JSON.stringify({ id: 'gen-c', object: 'chat.completion', model: body.model, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'OK' } }], usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4, ...cost } }));
  });
  return { server, seen };
}

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'online-suffix-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { text: '' };
  child.stdout.on('data', (d) => { logs.text += d; });
  child.stderr.on('data', (d) => { logs.text += d; });
  env = { dir, hp, or, child, logs, inboundPort };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of [env.hp.server, env.or.server]) s.closeAllConnections?.();
  await Promise.all([env.hp.server, env.or.server].map((s) => new Promise((r) => s.close(r))));
  rmSync(env.dir, { recursive: true, force: true });
});

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for ${what}\n${env?.logs.text ?? ''}`);
}

let seq = 0;
/** `build(id)` returns the body; the id is also the prompt, which is how the upstream body is found again. */
function post(path, build) {
  const id = `online-${++seq}`;
  const payload = Buffer.from(JSON.stringify(build(id)));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-api-key': 'ppq-test-key', 'x-query-source': 'api', 'x-request-id': id,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', async () => {
        const text = Buffer.concat(chunks).toString('utf8');
        assert.equal(res.statusCode, 200, text);
        const settle = await waitFor(() => env.hp.settles.find((s) => s.request_id === id), `the settle for ${id}`);
        const sent = await waitFor(() => env.or.seen.find((s) => s.requestId === id), `the upstream body for ${id}`);
        resolve({ settle, sent });
      });
    });
    r.on('error', reject);
    r.end(payload);
  });
}

const chat = (model, extra = {}) =>
  post('/v1/chat/completions', (id) => ({ model, messages: [{ role: 'user', content: id }], ...extra }));
const responses = (model, extra = {}) => post('/v1/responses', (id) => ({ model, input: id, ...extra }));
const messages = (model, extra = {}) =>
  post('/v1/messages', (id) => ({ model, max_tokens: 50, messages: [{ role: 'user', content: id }], ...extra }));

test('chat: :online becomes the web plugin (Exa defaults applied) and settles online', { skip: SKIP }, async () => {
  const { settle, sent } = await chat('deepseek/deepseek-v4-flash:online');
  assert.equal(sent.path, '/api/v1/chat/completions');
  assert.equal(sent.body.model, 'deepseek/deepseek-v4-flash', 'the suffix never reaches the upstream');
  assert.deepEqual(sent.body.plugins, [{ id: 'web', engine: 'exa', mode: 'fast' }]);
  assert.equal(settle.is_online, true);
});

test('chat: on a Claude model the plugin rides the #676 swap onto the server tool', { skip: SKIP }, async () => {
  const { settle, sent } = await chat('~anthropic/claude-fable-latest:online');
  assert.equal(sent.body.plugins, undefined, 'no plugin left to 400 a multi-turn conversation');
  assert.ok(sent.body.tools?.some((t) => t.type === 'openrouter:web_search'), JSON.stringify(sent.body.tools));
  assert.equal(settle.is_online, true);
});

test('chat: a caller-sent web plugin keeps its own options; no second plugin is added', { skip: SKIP }, async () => {
  const { sent } = await chat('deepseek/deepseek-v4-flash:online', { plugins: [{ id: 'web', max_results: 5 }] });
  assert.deepEqual(sent.body.plugins, [{ id: 'web', max_results: 5, engine: 'exa', mode: 'fast' }]);
});

test('chat: without the directive nothing is added (no suffix, or an hp that predates it)', { skip: SKIP }, async () => {
  const plain = await chat('deepseek/deepseek-v4-flash');
  assert.equal(plain.sent.body.plugins, undefined);
  assert.equal(plain.settle.is_online, false);
  const legacy = await chat('legacy/model:online');
  assert.equal(legacy.sent.body.plugins, undefined);
  assert.equal(legacy.settle.is_online, false);
});

test('responses: :online becomes the Exa web plugin, as hp sent it before #280, and settles online', { skip: SKIP }, async () => {
  const { settle, sent } = await responses('deepseek/deepseek-v4-flash:online');
  assert.equal(sent.path, '/api/v1/responses');
  assert.equal(sent.body.model, 'deepseek/deepseek-v4-flash');
  assert.deepEqual(sent.body.plugins, [{ id: 'web', engine: 'exa', mode: 'fast' }]);
  assert.equal(sent.body.tools, undefined);
  assert.equal(settle.is_online, true);
});

test('responses: on a Claude model the search rides the #676 swap onto the server tool', { skip: SKIP }, async () => {
  const { settle, sent } = await responses('~anthropic/claude-fable-latest:online');
  assert.equal(sent.body.model, '~anthropic/claude-fable-latest');
  assert.equal(sent.body.plugins, undefined);
  assert.deepEqual(sent.body.tools, [{ type: 'openrouter:web_search', parameters: {} }]);
  assert.equal(settle.is_online, true);
});

test('responses: a body already asking for search is left as it is', { skip: SKIP }, async () => {
  const { settle, sent } = await responses('openai/gpt-5.5:online', { tools: [{ type: 'web_search' }] });
  assert.equal(sent.body.plugins, undefined, 'never searched twice');
  assert.deepEqual(sent.body.tools, [{ type: 'web_search' }]);
  assert.equal(settle.is_online, true);
});

test('responses: without the directive nothing is added, and a caller plugin still counts as online', { skip: SKIP }, async () => {
  const plain = await responses('openai/gpt-5.5');
  assert.equal(plain.sent.body.plugins, undefined);
  assert.equal(plain.settle.is_online, false);
  const plugin = await responses('openai/gpt-5.5', { plugins: [{ id: 'web', max_results: 5 }] });
  assert.deepEqual(plugin.sent.body.plugins, [{ id: 'web', max_results: 5 }]);
  assert.equal(plugin.settle.is_online, true);
});

test('messages: :online becomes Anthropic’s dated web search tool, not the ignored plugin', { skip: SKIP }, async () => {
  const { settle, sent } = await messages('moonshotai/kimi-k3:online', { tools: [{ name: 'calc', input_schema: { type: 'object' } }] });
  assert.equal(sent.path, '/api/v1/messages');
  assert.equal(sent.body.model, 'moonshotai/kimi-k3');
  assert.equal(sent.body.plugins, undefined);
  assert.deepEqual(sent.body.tools, [
    { name: 'calc', input_schema: { type: 'object' } },
    { type: 'web_search_20250305', name: 'web_search' },
  ]);
  assert.equal(settle.is_online, true);
});

test('messages: a declared search tool is kept as the only one', { skip: SKIP }, async () => {
  const declared = { type: 'web_search_20260209', name: 'web_search', max_uses: 2 };
  const { sent } = await messages('anthropic/claude-sonnet-5:online', { tools: [declared] });
  assert.deepEqual(sent.body.tools, [declared]);
});

// ── is_byok + web_search_engine on the settle (horse-power #1088) ────────────
// The fee's two inputs ride every OpenRouter settle: the cost regime the usage
// frame reported, and which engine the body actually sent runs its search on.

test('settle: the engine is judged on the body sent (exa for the plugin, native after the Claude swap or the dated tool, absent without a search)', { skip: SKIP }, async () => {
  const exa = await chat('deepseek/deepseek-v4-flash:online');
  assert.equal(exa.settle.web_search_engine, 'exa');
  assert.equal(exa.settle.is_byok, false, 'OpenRouter’s cost was billed, Exa included');
  // sonnet-4.6 keeps the Exa plugin (the #676 swap covers only the models the
  // plugin breaks); fable-latest is swapped onto the server tool.
  const sonnet = await chat('anthropic/claude-sonnet-4.6:online');
  assert.equal(sonnet.settle.web_search_engine, 'exa');
  const claude = await chat('~anthropic/claude-fable-latest:online');
  assert.equal(claude.settle.web_search_engine, 'native', 'the swapped server tool is the provider’s own search');
  const plain = await chat('deepseek/deepseek-v4-flash');
  assert.equal(plain.settle.web_search_engine, undefined);
  assert.equal(plain.settle.is_byok, false);
  const r = await responses('openai/gpt-5.5:online');
  assert.equal(r.settle.web_search_engine, 'exa');
  assert.equal(r.settle.is_byok, false);
  const m = await messages('anthropic/claude-sonnet-4.6:online');
  assert.equal(m.settle.web_search_engine, 'native', 'the dated tool is the provider’s own search');
  assert.equal(m.settle.is_byok, false);
  const mPlain = await messages('anthropic/claude-sonnet-4.6');
  assert.equal(mPlain.settle.web_search_engine, undefined);
});

test('settle: a disabled web plugin is not a search (horse-power #1094): offline, no engine, sent as the caller wrote it', { skip: SKIP }, async () => {
  const off = await chat('deepseek/deepseek-v4-flash', { plugins: [{ id: 'web', engine: 'exa', enabled: false }] });
  assert.equal(off.settle.is_online, false);
  assert.equal(off.settle.web_search_engine, undefined);
  assert.deepEqual(off.sent.body.plugins, [{ id: 'web', engine: 'exa', enabled: false }], 'passed through untouched: no Exa defaults, no swap');
  // The same entry beside `:online`: the suffix wins and the disabled sibling is dropped.
  const on = await chat('deepseek/deepseek-v4-flash:online', { plugins: [{ id: 'web', enabled: false }] });
  assert.equal(on.settle.is_online, true);
  assert.equal(on.settle.web_search_engine, 'exa');
  assert.deepEqual(on.sent.body.plugins, [{ id: 'web', engine: 'exa', mode: 'fast' }]);
  const r = await responses('openai/gpt-5.5', { plugins: [{ id: 'web', enabled: false }] });
  assert.equal(r.settle.is_online, false);
  assert.equal(r.settle.web_search_engine, undefined);
});

test('settle: a BYOK usage frame marks is_byok on every dialect, with the engine beside it', { skip: SKIP }, async () => {
  const c = await chat('byok/deepseek-v4-flash:online');
  assert.equal(c.settle.is_byok, true);
  assert.equal(c.settle.web_search_engine, 'exa');
  assert.equal(c.settle.total_cost_usd, 0.0001, 'the upstream inference cost, not OpenRouter’s');
  const r = await responses('byok/gpt-5.5:online');
  assert.equal(r.settle.is_byok, true);
  assert.equal(r.settle.web_search_engine, 'exa');
  const m = await messages('byok/claude-sonnet-4.6');
  assert.equal(m.settle.is_byok, true);
  assert.equal(m.settle.web_search_engine, undefined);
});
