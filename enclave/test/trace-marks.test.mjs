// The two generation marks on a real request, as the backend receives them on
// the settle (or the error report): `t_upstream_sent_ms` is taken right before
// the first upstream request actually ISSUED — a candidate passed over before
// sending never sets it, and the next candidate does not move it — and
// `t_first_content_ms` / `first_token_kind` come from the first upstream frame
// carrying generated text, never from a keep-alive or a role-only delta.
//
// Drives the real server against a fake backend and fake upstreams, like
// report-context.test.mjs.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

const CREDIT = '00000000-0000-4000-8000-000000000001';
const TINFOIL_HOST = 'inference.tinfoil.sh';
const FIREWORKS_HOST = 'api.fireworks.ai';
/** How long the failing direct candidate takes to answer 500. */
const FW_FAIL_DELAY_MS = 300;
/** Gap between the role-only preamble and the first text frame. */
const PREAMBLE_GAP_MS = 150;

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

/** Fake backend: /authorize picks the candidate list by model; settles and reports are recorded. */
function fakeHp(tls) {
  const settles = [];
  const errors = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      const m = body.model;
      const answer = {
        authorized: true, credit_id: CREDIT, api_key_id: 'key-under-test',
        resolved_model: m, is_free: false, upstreams: [],
      };
      // Tinfoil with no attestation service reachable: skipped before sending.
      if (m === 'private/attest') answer.upstreams = [{ provider: 'tinfoil', host: TINFOIL_HOST, key_ref: 'tinfoil' }];
      // A direct candidate that is ISSUED and fails, then OpenRouter serves.
      if (m === 'test/fw-fail') {
        answer.upstreams = [{
          provider: 'fireworks', host: FIREWORKS_HOST, path: '/inference/v1/chat/completions',
          key_ref: 'fireworks', upstream_model: 'accounts/fireworks/models/test', or_slug: m,
        }];
      }
      // A direct candidate with no key provisioned: skipped, never sent.
      if (m === 'test/skip-then-or') {
        answer.upstreams = [{
          provider: 'fireworks', host: FIREWORKS_HOST, path: '/inference/v1/chat/completions',
          key_ref: 'not-provisioned', upstream_model: 'x', or_slug: m,
        }];
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(answer));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors };
}

const sse = (obj) => `data: ${JSON.stringify(obj)}\n\n`;
const delta = (d, extra = {}) => sse({ id: 'gen-1', object: 'chat.completion.chunk', model: 'openai/gpt-4o-mini', choices: [{ index: 0, delta: d }], ...extra });

/** Fake OpenRouter: behaviour chosen by the model in the body. */
function fakeOpenRouter(tls) {
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    const m = body.model;
    if (m === 'test/stream-reasoning' || m === 'test/stream-noprov') {
      const provider = m === 'test/stream-reasoning' ? { provider: 'OpenAI' } : {};
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      // What precedes the first token: a keep-alive and a role-only delta.
      res.write(': OPENROUTER PROCESSING\n\n');
      res.write(delta({ role: 'assistant', content: '' }, provider));
      await sleep(PREAMBLE_GAP_MS);
      res.write(delta({ reasoning: 'Thinking it over' }, provider));
      res.write(delta({ content: 'Answer' }, provider));
      res.write(sse({ id: 'gen-1', model: 'openai/gpt-4o-mini', choices: [], usage: { prompt_tokens: 3, completion_tokens: 5, cost: 0.001 }, ...provider }));
      return res.end('data: [DONE]\n\n');
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({
      id: 'gen-1', object: 'chat.completion', model: m, provider: 'Google AI Studio',
      choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    }));
  });
  return { server };
}

/** Fake direct provider: answers 500 after a delay, so the attempt is visibly inside the window. */
function fakeFireworks(tls) {
  const hits = { n: 0 };
  const server = https.createServer(tls, async (req, res) => {
    await readBody(req);
    hits.n++;
    await sleep(FW_FAIL_DELAY_MS);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end('{"error":{"message":"overloaded"}}');
  });
  return { server, hits };
}

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'trace-marks-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost',
    '-addext', `subjectAltName=DNS:localhost,DNS:${TINFOIL_HOST},DNS:${FIREWORKS_HOST}`,
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, fwPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const fw = fakeFireworks(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(fw.server, fwPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      FIREWORKS_PORT: String(fwPort), FIREWORKS_API_KEY: 'test-fw-key',
      TINFOIL_API_KEY: 'test-tinfoil-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { text: '' };
  child.stdout.on('data', (d) => { logs.text += d; });
  child.stderr.on('data', (d) => { logs.text += d; });
  env = { dir, hp, or, fw, child, logs, inboundPort };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of [env.hp.server, env.or.server, env.fw.server]) s.closeAllConnections?.();
  await Promise.all([env.hp.server, env.or.server, env.fw.server].map((s) => new Promise((r) => s.close(r))));
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
const nextId = (tag) => `tm-${tag}-${++seq}`;

function chat(id, model, { stream = false } = {}) {
  const payload = Buffer.from(JSON.stringify({ model, stream, messages: [{ role: 'user', content: 'hi' }] }));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path: '/v1/chat/completions', method: 'POST',
      rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-credit-id': CREDIT, 'x-query-source': 'api', 'x-request-id': id,
      },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
      res.on('error', () => resolve(res.statusCode));
    });
    r.on('error', reject);
    r.end(payload);
  });
}
const settleFor = (id) => waitFor(() => env.hp.settles.find((s) => s.request_id === id), `the settle for ${id}`);

test('streamed: the first token is the first text frame, not the keep-alive or role-only delta', { skip: SKIP }, async () => {
  const id = nextId('stream');
  assert.equal(await chat(id, 'test/stream-reasoning', { stream: true }), 200);
  const { trace } = await settleFor(id);
  assert.equal(Number.isInteger(trace.t_upstream_sent_ms), true, JSON.stringify(trace));
  assert.ok(trace.t_upstream_sent_ms <= trace.t_upstream_connect_ms, 'sent before the headers came back');
  assert.equal(trace.first_token_kind, 'reasoning', 'the reasoning frame came first');
  // The role-only delta went out at once; the first token waited the gap.
  assert.ok(
    trace.t_first_content_ms - trace.t_upstream_sent_ms >= PREAMBLE_GAP_MS - 20,
    `ttft ${trace.t_first_content_ms - trace.t_upstream_sent_ms} ms: ${JSON.stringify(trace)}`,
  );
  assert.ok(trace.t_first_content_ms <= trace.t_total_ms);
});

test('non-streamed JSON body: sent is marked, there is no first token', { skip: SKIP }, async () => {
  const id = nextId('json');
  assert.equal(await chat(id, 'test/json'), 200);
  const { trace } = await settleFor(id);
  assert.equal(Number.isInteger(trace.t_upstream_sent_ms), true);
  assert.equal(trace.t_first_content_ms, null);
  assert.equal(trace.first_token_kind, null);
});

test('an issued direct attempt that fails keeps the mark; the next candidate does not move it', { skip: SKIP }, async () => {
  const id = nextId('fwfail');
  const before = env.fw.hits.n;
  assert.equal(await chat(id, 'test/fw-fail'), 200);
  const settle = await settleFor(id);
  const { trace } = settle;
  assert.equal(env.fw.hits.n, before + 1, 'the direct candidate was actually sent');
  assert.deepEqual(trace.route.failed, [{ provider: 'fireworks', status: 500, class: 'http_5xx' }]);
  assert.equal(trace.route.chosen, 'openrouter');
  // Sent at the FIRST attempt: the failed one sits inside the window.
  assert.ok(
    trace.t_upstream_connect_ms - trace.t_upstream_sent_ms >= FW_FAIL_DELAY_MS - 20,
    JSON.stringify(trace),
  );
});

test('a candidate skipped before sending never sets the mark', { skip: SKIP }, async () => {
  // Tinfoil skipped at attestation and nothing after it: nothing was sent.
  const id = nextId('attest');
  assert.equal(await chat(id, 'private/attest'), 502);
  const final = await waitFor(
    () => env.hp.errors.find((e) => e.trace?.client_request_id === id && e.terminal === true),
    `the final report for ${id}`,
  );
  assert.equal(final.trace.t_upstream_sent_ms, null, JSON.stringify(final.trace));
  assert.equal(final.trace.t_first_content_ms, null);
  assert.equal(final.trace.first_token_kind, null);
  const early = env.hp.errors.find((e) => e.trace?.client_request_id === id && e.terminal === false);
  assert.equal(early.trace.t_upstream_sent_ms, null, 'nor did the skip report');

  // A skipped direct candidate ahead of OpenRouter: the mark is OpenRouter's.
  const id2 = nextId('skip');
  const hits = env.fw.hits.n;
  assert.equal(await chat(id2, 'test/skip-then-or'), 200);
  assert.equal(env.fw.hits.n, hits, 'the skipped candidate was never sent');
  const { trace } = await settleFor(id2);
  assert.equal(trace.route.skipped[0].reason, 'no_tunnel_or_key');
  assert.equal(Number.isInteger(trace.t_upstream_sent_ms), true);
  assert.ok(trace.t_upstream_sent_ms <= trace.t_upstream_connect_ms);
});

test('source pin: upstreamSent is marked once, right before the chat loop issues a request', () => {
  const SRC = readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8');
  const sites = [...SRC.matchAll(/traceRec\.mark\('upstreamSent'\)/g)];
  // Two: the chat loop, and the one-upstream /v1/messages handler (#275),
  // which marks it right before its own attemptUpstream.
  assert.equal(sites.length, 2);
  const after = SRC.slice(sites[0].index).split('\n').slice(1).map((l) => l.trim()).filter((l) => l && !l.startsWith('//'));
  assert.match(after[0], /^let attempt = await attemptUpstream\(spec\.opts, spec\.bodyStr\);$/);
  const afterMessages = SRC.slice(sites[1].index).split('\n').slice(1).map((l) => l.trim()).filter((l) => l && !l.startsWith('//'));
  assert.match(afterMessages[0], /^const attempt = await attemptUpstream\($/);
  // Every skip of the loop (`continue`) comes before it.
  const loop = SRC.slice(SRC.indexOf('for (let i = 0; i < candidates.length; i++)'), sites[0].index);
  assert.ok((loop.match(/continue;/g) || []).length >= 2, 'the skips precede the mark');
});

// ── upstream_provider on the settle ───────────────────────────────────────

test('settle: upstream_provider carries who answered behind OpenRouter; provider keeps its meaning', { skip: SKIP }, async () => {
  const id = nextId('prov-stream');
  assert.equal(await chat(id, 'test/stream-reasoning', { stream: true }), 200);
  const settle = await settleFor(id);
  assert.equal(settle.provider, 'openrouter');
  assert.equal(settle.upstream_provider, 'OpenAI');

  const id2 = nextId('prov-json');
  assert.equal(await chat(id2, 'test/json'), 200);
  const s2 = await settleFor(id2);
  assert.equal(s2.provider, 'openrouter');
  assert.equal(s2.upstream_provider, 'Google AI Studio');
});

test('settle: upstream_provider is present and null when no usage chunk named one', { skip: SKIP }, async () => {
  const id = nextId('prov-none');
  assert.equal(await chat(id, 'test/stream-noprov', { stream: true }), 200);
  const settle = await settleFor(id);
  assert.equal('upstream_provider' in settle, true, 'present, so null means "not reported"');
  assert.equal(settle.upstream_provider, null);
  assert.equal(settle.provider, 'openrouter');
});
