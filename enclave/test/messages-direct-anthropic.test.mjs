// #450: on the in-enclave /v1/messages route an Anthropic first-party
// candidate hp offers is tried FIRST, through the Anthropic tunnel with the
// enclave's Anthropic key, on the candidate's own /v1/messages; OpenRouter
// stays the fallback. Anthropic speaks the dialect natively, so the body goes
// as is; what this file pins down is the credential shape (x-api-key + a
// version header, never Bearer), the dated model echo rewritten to the public
// slug, the settle, and the fall-through when Anthropic refuses. Driven end to
// end like messages-direct-fireworks.test.mjs: the real server against a fake
// horse-power, a fake Anthropic and a fake OpenRouter.
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

// hp serves the model under the undated id; Anthropic echoes the dated snapshot.
const UPSTREAM_ID = 'claude-opus-5-5';
const ECHOED_ID = 'claude-opus-5-5-20260921';
const SLUG = 'anthropic/claude-opus-5.5';

/** Fake horse-power: an Anthropic candidate ahead of OpenRouter for the model; records the rest. */
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
        provider_directive: null,
        upstreams: [
          { provider: 'anthropic', api_style: 'anthropic', host: 'api.anthropic.com', path: '/v1/messages', key_ref: 'anthropic',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: true, context_length: 1000000, tier: 'default' },
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

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
// Anthropic's own convention: the input side (and both cache buckets) on
// message_start, the output count on message_delta; `msg_…` ids.
const AN_START = { type: 'message_start', message: { id: 'msg_an1', type: 'message', role: 'assistant', content: [], model: ECHOED_ID, stop_reason: null, stop_sequence: null, usage: { input_tokens: 12, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 2 } } };
const AN_END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3 } },
  { type: 'message_stop' },
];
const AN_JSON = { id: 'msg_an2', type: 'message', role: 'assistant', model: ECHOED_ID, content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 12, output_tokens: 3, cache_read_input_tokens: 4, cache_creation_input_tokens: 2 } };
const OR_START = { type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model: SLUG, provider: 'Anthropic', stop_reason: null, usage: { input_tokens: 12, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } } };
const OR_END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];
const DELTAS = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_stop', index: 0 },
];

/** Fake Anthropic: `/v1/messages` streams (or answers one JSON body), or refuses with 529; any other path is a 404. */
function fakeAnthropic({ key, cert }) {
  let mode = 'serve';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/v1/messages') { res.writeHead(404); return res.end(); }
    if (mode === 'overloaded') {
      res.writeHead(529, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }));
    }
    if (body.stream !== true) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(AN_JSON));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(AN_START));
    for (const d of DELTAS) res.write(sse(d));
    for (const e of AN_END) res.write(sse(e));
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

/** POST as a native client; a header set to undefined is NOT sent. */
function post(port, path, body, headers = {}) {
  const payload = JSON.stringify(body);
  const merged = {
    'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
    'x-api-key': 'ppq-test-key', 'x-query-source': 'api', 'anthropic-version': '2023-06-01', ...headers,
  };
  for (const k of Object.keys(merged)) if (merged[k] === undefined) delete merged[k];
  return new Promise((resolve, reject) => {
    const r = https.request({ host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false, headers: merged }, (res) => {
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

test('/v1/messages: an Anthropic first-party candidate serves the dialect direct, OpenRouter stays the fallback (#450)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-direct-anthropic-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.anthropic.com',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, anPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const an = fakeAnthropic(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(an.server, anPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      ANTHROPIC_PORT: String(anPort), ANTHROPIC_API_KEY: 'anthropic-test-key',
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

    // 1. Served direct: Anthropic got the projected body on its own
    // /v1/messages with the enclave's key in Anthropic's header shape; the
    // client got Anthropic's frames with the dated echo rewritten to the
    // public slug; hp was told to price the additive counts against the row.
    const direct = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-direct', 'anthropic-beta': 'interleaved-thinking-2025-05-14' });
    assert.equal(direct.status, 200, direct.body);
    assert.match(direct.headers['content-type'], /text\/event-stream/);
    const expected = [AN_START, ...DELTAS, ...AN_END].map(sse).join('').replace(`"model":"${ECHOED_ID}"`, `"model":"${SLUG}"`);
    assert.equal(direct.body, expected, 'Anthropic’s frames, the dated wire id rewritten to the public slug');
    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');
    const sent = an.seen.find((s) => s.path === '/v1/messages');
    assert.ok(sent, 'the request reached Anthropic’s own /v1/messages, the candidate’s path');
    assert.equal(sent.headers['x-api-key'], 'anthropic-test-key', 'the enclave’s Anthropic key, in Anthropic’s header');
    assert.equal(sent.headers.authorization, undefined, 'never a Bearer credential, never the caller’s key');
    assert.equal(sent.headers['anthropic-version'], '2023-06-01', 'the caller’s version header rides through');
    assert.equal(sent.headers['anthropic-beta'], 'interleaved-thinking-2025-05-14', 'the caller’s beta header rides through');
    assert.equal(sent.headers['x-session-affinity'], undefined, 'the Fireworks affinity hint is not sent to Anthropic');
    assert.equal(sent.body.model, UPSTREAM_ID, 'the projected body names the wire model');
    assert.equal(sent.body.max_tokens, 50, 'hp’s cap landed before projection');
    assert.equal(sent.body.stream, true);
    assert.equal('stream_options' in sent.body, false);
    assert.equal('provider' in sent.body, false);
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct'), `the direct settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.provider, 'anthropic');
    assert.equal(settle.route, 'direct');
    assert.equal(settle.route_bail_reason, 'none');
    assert.equal(settle.direct_provider, 'anthropic');
    assert.equal(settle.cost_source, 'catalog-tokens');
    assert.equal(settle.total_cost_usd, 0);
    assert.equal(settle.generation_id, '');
    assert.equal(settle.model, SLUG, 'settled under the public slug hp priced');
    assert.equal(settle.upstream_model, UPSTREAM_ID);
    assert.equal(settle.served_model, ECHOED_ID, 'the raw dated echo, for hp’s mismatch tripwire (it strips the date)');
    assert.equal(settle.upstream_provider, null);
    assert.equal(settle.input_tokens, 12, 'message_start’s input side');
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.cache_write_tokens, 2);
    assert.equal(settle.output_tokens, 3, 'message_delta’s output count');
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.route?.chosen, 'anthropic');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-direct'), false, 'a clean direct answer reports nothing');

    // 2. A native caller that sent no version header: Anthropic requires one,
    // so the relay fills the pinned default rather than letting the upstream
    // 400 and the request fall to OpenRouter.
    const noVersion = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-noversion', 'anthropic-version': undefined });
    assert.equal(noVersion.status, 200, noVersion.body);
    const sentNoVersion = an.seen.at(-1);
    assert.equal(sentNoVersion.headers['anthropic-version'], '2023-06-01', 'the default version when the caller sent none');
    assert.equal(or.seen.length, 0);
    await waitFor(() => hp.settles.find((s) => s.request_id === 'req-noversion'), `the no-version settle\n${logs}`);
    // …and a caller's own, non-default version is preserved, never replaced
    // by the pinned one.
    const ownVersion = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-ownversion', 'anthropic-version': '2024-10-22' });
    assert.equal(ownVersion.status, 200, ownVersion.body);
    assert.equal(an.seen.at(-1).headers['anthropic-version'], '2024-10-22', 'the caller’s version wins over the default');
    await waitFor(() => hp.settles.find((s) => s.request_id === 'req-ownversion'), `the own-version settle\n${logs}`);

    // 3. Non-streaming: one JSON body straight through, the echo rewritten,
    // the settle built from its complete usage.
    const plain = await post(inboundPort, '/v1/messages', REQ({ stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(plain.status, 200, plain.body);
    assert.match(plain.headers['content-type'], /application\/json/);
    const answer = JSON.parse(plain.body);
    assert.equal(answer.model, SLUG, 'the dated echo rewritten in the JSON body too');
    assert.equal(answer.content[0].text, 'OK');
    assert.equal(an.seen.at(-1).body.stream, false);
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the JSON settle\n${logs}`);
    assert.equal(jsonSettle.provider, 'anthropic');
    assert.equal(jsonSettle.served_model, ECHOED_ID);
    assert.equal(jsonSettle.input_tokens, 12);
    assert.equal(jsonSettle.cache_read_tokens, 4);
    assert.equal(jsonSettle.cache_write_tokens, 2);
    assert.equal(jsonSettle.output_tokens, 3);
    assert.equal(or.seen.length, 0);

    // 4. An image block on a row that advertises vision is served direct
    // (Anthropic is an image-capable direct provider on this dialect).
    const withImage = REQ({ messages: [{ role: 'user', content: [{ type: 'text', text: 'what is this?' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'QUJD' } }] }] });
    const imaged = await post(inboundPort, '/v1/messages', withImage, { 'x-request-id': 'req-image' });
    assert.equal(imaged.status, 200, imaged.body);
    const imageSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-image'), `the image settle\n${logs}`);
    assert.equal(imageSettle.provider, 'anthropic');
    assert.equal(imageSettle.route_bail_reason, 'none');
    assert.equal(an.seen.at(-1).body.messages[0].content[1].type, 'image', 'the image block went to Anthropic as is');

    // 5. Anthropic overloaded (529): drained, never relayed; OpenRouter serves
    // the same request, and the settle says why the direct seam was not taken.
    an.setMode('overloaded');
    const fellBack = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-fallback' });
    assert.equal(fellBack.status, 200, fellBack.body);
    assert.equal(fellBack.body, [OR_START, ...DELTAS, ...OR_END].map(sse).join(''), 'OpenRouter’s frames, untouched');
    assert.equal(or.seen.length, 1);
    assert.equal(or.seen[0].headers.authorization, 'Bearer or-test-key');
    assert.equal(or.seen[0].headers['x-api-key'], undefined, 'the Anthropic key never reaches OpenRouter');
    const fallbackSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-fallback'), `the fallback settle\n${logs}`);
    assert.equal(fallbackSettle.provider, 'openrouter');
    assert.equal(fallbackSettle.route, 'openrouter');
    assert.equal(fallbackSettle.route_bail_reason, 'attempt_failed');
    assert.equal(fallbackSettle.cost_source, 'messages-usage');
    assert.equal(fallbackSettle.total_cost_usd, 0.00021);
    assert.deepEqual(fallbackSettle.trace?.route?.failed?.map((f) => [f.provider, f.status]), [['anthropic', 529]]);
    assert.equal(fallbackSettle.trace?.route?.chosen, 'openrouter');
    an.setMode('serve');

    // 6. A web search (Anthropic's dated server tool) only runs where
    // OpenRouter routes it: the candidate is skipped, not tried.
    const before = an.seen.length;
    const searched = await post(inboundPort, '/v1/messages', REQ({ tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }] }), { 'x-request-id': 'req-search' });
    assert.equal(searched.status, 200, searched.body);
    const searchSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-search'), `the search settle\n${logs}`);
    assert.equal(searchSettle.provider, 'openrouter');
    assert.equal(searchSettle.route_bail_reason, 'web_search_requires_openrouter');
    assert.equal(an.seen.length, before, 'Anthropic never saw the search tool');
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, an.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
