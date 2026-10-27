// hp #1139 phase 2: on the in-enclave /v1/messages route a Fireworks
// candidate hp offers is tried FIRST, through the Fireworks tunnel with the
// Fireworks key, on Fireworks' own /v1/messages; OpenRouter stays the
// fallback. Driven end to end like messages-route.test.mjs: the real server
// against a fake horse-power, a fake Fireworks and a fake OpenRouter. What is
// asserted is the contract — what each upstream was sent, what the client
// got back, what hp is told at settle, and the skip/fail records when the
// request could not ride the direct seam.
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

const UPSTREAM_ID = 'accounts/fireworks/models/kimi-k3';
const SLUG = 'moonshotai/kimi-k3';

/** Fake horse-power: a Fireworks candidate ahead of OpenRouter for kimi-k3; records the rest. */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  let supportsImageInput = false;
  let hardPin = null;
  // When set, authorize resolves the caller's id onto kimi-k3: how an hp
  // would pair a request for another family with the Fireworks host.
  let resolveTo = null;
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: resolveTo ?? body.model, is_free: false, web_search: false, max_tokens_cap: 50,
        provider_directive: hardPin,
        upstreams: [
          { provider: 'fireworks', api_style: 'openai', host: 'api.fireworks.ai', path: '/v1/chat/completions', key_ref: 'fireworks',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: supportsImageInput, context_length: 131072, tier: 'default' },
          { provider: 'openrouter', api_style: 'openai', host: 'openrouter.ai', path: '/api/v1/chat/completions', key_ref: 'openrouter', upstream_model: SLUG },
        ],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, setImages: (v) => { supportsImageInput = v; }, setHardPin: (v) => { hardPin = v; }, setResolveTo: (v) => { resolveTo = v; } };
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
// Fireworks' convention (hp #727 probe): zeros on message_start, the full
// counts on message_delta; ids are `msg_…`, never OpenRouter's `gen-…`.
const FW_START = { type: 'message_start', message: { id: 'msg_fw1', type: 'message', role: 'assistant', content: [], model: UPSTREAM_ID, stop_reason: null, usage: { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 } } };
const FW_END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { input_tokens: 12, output_tokens: 3, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } },
  { type: 'message_stop' },
];
const OR_START = { type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model: SLUG, provider: 'Fireworks', stop_reason: null, usage: { input_tokens: 12, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } } };
const OR_END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];
const DELTAS = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_stop', index: 0 },
];

/** Fake Fireworks `/v1/messages`: a streamed answer, or a refused status. */
function fakeFireworks({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/v1/messages') { res.writeHead(404); return res.end(); }
    if (mode === 'status500') {
      res.writeHead(500, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: 'Fireworks is down' } }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(FW_START));
    for (const d of DELTAS) res.write(sse(d));
    for (const e of FW_END) res.write(sse(e));
    res.end();
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

/** Fake OpenRouter `/api/v1/messages`: the fallback, always a clean streamed answer. */
function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/api/v1/messages') { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(OR_START));
    for (const d of DELTAS) res.write(sse(d));
    for (const e of OR_END) res.write(sse(e));
    res.end();
  });
  return { server, seen };
}

function post(port, path, body, headers = {}) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-api-key': 'ppq-test-key', 'x-query-source': 'api', 'anthropic-version': '2023-06-01', ...headers,
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

const REQ = (extra = {}) => ({ model: SLUG, max_tokens: 200, stream: true, messages: [{ role: 'user', content: 'Say OK.' }], ...extra });

test('/v1/messages: a Fireworks candidate serves the dialect direct, OpenRouter stays the fallback (hp #1139 phase 2)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-direct-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  // One certificate for every fake: the enclave reaches Fireworks by its real
  // name through the tunnel, so that name has to be on it too.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.fireworks.ai',
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
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      FIREWORKS_PORT: String(fwPort), FIREWORKS_API_KEY: 'fireworks-test-key',
      OPENROUTER_API_KEY: 'or-test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. Served direct: Fireworks got the projected body with the enclave's
    // Fireworks key; the client got Fireworks' frames under the public slug;
    // hp was told to price the counts against the Fireworks row.
    const direct = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-direct' });
    assert.equal(direct.status, 200, direct.body);
    assert.match(direct.headers['content-type'], /text\/event-stream/);
    const expected = [FW_START, ...DELTAS, ...FW_END].map(sse).join('').replaceAll(UPSTREAM_ID, SLUG);
    assert.equal(direct.body, expected, 'Fireworks’ frames, the wire model id rewritten to the public slug');
    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');
    const sent = fw.seen.find((s) => s.path === '/v1/messages');
    assert.ok(sent, 'the request reached Fireworks’ own /v1/messages');
    assert.equal(sent.headers.authorization, 'Bearer fireworks-test-key', 'the Fireworks key, never OpenRouter’s or the caller’s');
    assert.equal(sent.headers['anthropic-version'], '2023-06-01', 'the dialect’s version header rides through');
    assert.ok(typeof sent.headers['x-session-affinity'] === 'string' && sent.headers['x-session-affinity'].length > 0, 'prompt-cache affinity (#286) on the Fireworks dialect');
    assert.equal(sent.body.model, UPSTREAM_ID, 'the projected body names the wire model');
    assert.equal(sent.body.max_tokens, 50, 'hp’s cap landed before projection');
    assert.equal(sent.body.stream, true);
    assert.equal('stream_options' in sent.body, false, 'no OpenAI accounting field on the Messages dialect');
    assert.equal('provider' in sent.body, false);
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct'), `the direct settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.provider, 'fireworks');
    assert.equal(settle.route, 'direct');
    assert.equal(settle.route_bail_reason, 'none');
    assert.equal(settle.direct_provider, 'fireworks');
    assert.equal(settle.cost_source, 'catalog-tokens');
    assert.equal(settle.total_cost_usd, 0);
    assert.equal(settle.generation_id, '');
    assert.equal(settle.model, SLUG, 'settled under the public slug hp priced');
    assert.equal(settle.upstream_model, UPSTREAM_ID);
    assert.equal(settle.served_model, UPSTREAM_ID, 'the raw wire id, for hp’s mismatch tripwire');
    assert.equal(settle.upstream_provider, null);
    assert.equal(settle.is_byok, undefined);
    assert.equal(settle.input_tokens, 12, 'message_delta’s counts win over message_start’s zeros');
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.output_tokens, 3);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.route?.chosen, 'fireworks');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-direct'), false, 'a clean direct answer reports nothing — not even usage-missing');

    // 2. Fireworks refuses: drained, never relayed; OpenRouter serves the same
    // request, and the settle says why the direct seam was not taken.
    fw.setMode('status500');
    const fellBack = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-fallback' });
    assert.equal(fellBack.status, 200, fellBack.body);
    assert.equal(fellBack.body, [OR_START, ...DELTAS, ...OR_END].map(sse).join(''), 'OpenRouter’s frames, untouched');
    assert.equal(or.seen.length, 1);
    assert.equal(or.seen[0].headers.authorization, 'Bearer or-test-key');
    const fallbackSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-fallback'), `the fallback settle\n${logs}`);
    assert.equal(fallbackSettle.provider, 'openrouter');
    assert.equal(fallbackSettle.route, 'openrouter');
    assert.equal(fallbackSettle.route_bail_reason, 'attempt_failed');
    assert.equal(fallbackSettle.cost_source, 'messages-usage');
    assert.equal(fallbackSettle.total_cost_usd, 0.00021);
    assert.deepEqual(fallbackSettle.trace?.route?.failed?.map((f) => [f.provider, f.status]), [['fireworks', 500]]);
    assert.equal(fallbackSettle.trace?.route?.chosen, 'openrouter');
    fw.setMode('stream');

    // 3. A web search (Anthropic's dated server tool) only runs where
    // OpenRouter routes it: the candidate is skipped, not tried.
    const searched = await post(inboundPort, '/v1/messages', REQ({ tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }] }), { 'x-request-id': 'req-search' });
    assert.equal(searched.status, 200, searched.body);
    const searchSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-search'), `the search settle\n${logs}`);
    assert.equal(searchSettle.provider, 'openrouter');
    assert.equal(searchSettle.route_bail_reason, 'web_search_requires_openrouter');
    assert.equal(fw.seen.filter((s) => s.body?.tools).length, 0, 'Fireworks never saw the search tool');

    // 4. The shared gate judges the body under the dialect's own rules: an
    // image block on a row without vision bails non_text_content, and the
    // request rides OpenRouter.
    const withImage = REQ({ messages: [{ role: 'user', content: [{ type: 'text', text: 'what is this?' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'QUJD' } }] }] });
    const imaged = await post(inboundPort, '/v1/messages', withImage, { 'x-request-id': 'req-image' });
    assert.equal(imaged.status, 200, imaged.body);
    const imageSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-image'), `the image settle\n${logs}`);
    assert.equal(imageSettle.provider, 'openrouter');
    assert.equal(imageSettle.route_bail_reason, 'non_text_content');
    assert.equal(imageSettle.direct_provider, undefined);

    // 5. A hard provider pin names where OpenRouter must route (hp #1060):
    // the direct candidate is skipped by name, and the pinned body goes to
    // OpenRouter with the pin on it.
    hp.setHardPin({ only: ['google-vertex'], allow_fallbacks: false });
    const pinned = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-pinned' });
    assert.equal(pinned.status, 200, pinned.body);
    const pinSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-pinned'), `the pinned settle\n${logs}`);
    assert.equal(pinSettle.provider, 'openrouter');
    assert.equal(pinSettle.route_bail_reason, 'hard_provider_pin');
    assert.deepEqual(or.seen.at(-1).body.provider, { only: ['google-vertex'], allow_fallbacks: false }, 'the pin rides the OpenRouter body');
    assert.equal(fw.seen.length, 2, 'Fireworks saw nothing new');
    hp.setHardPin(null);

    // 6. The family binding is judged on the CALLER's id too: a request for
    // an Anthropic model that hp resolved onto kimi-k3 must not reach the
    // Fireworks host, however the candidate list reads.
    hp.setResolveTo(SLUG);
    const bound = await post(inboundPort, '/v1/messages', REQ({ model: 'anthropic/claude-sonnet-4.6' }), { 'x-request-id': 'req-binding' });
    assert.equal(bound.status, 200, bound.body);
    const bindSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-binding'), `the binding settle\n${logs}`);
    assert.equal(bindSettle.provider, 'openrouter');
    assert.equal(bindSettle.route_bail_reason, 'upstream_not_bound_to_family');
    assert.equal(fw.seen.length, 2, 'Fireworks saw nothing new');
    const bindReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-binding'), `the binding report\n${logs}`);
    assert.equal(bindReport.code, 'upstream_unreachable');
    assert.equal(bindReport.terminal, false);
    hp.setResolveTo(null);
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, fw.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
