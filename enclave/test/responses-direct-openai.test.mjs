// horse-power #1156: on the in-enclave /v1/responses route an OpenAI candidate
// hp offers is tried FIRST, through the OpenAI tunnel with the OpenAI key, as
// an allowlisted pass-through to api.openai.com/v1/responses; OpenRouter stays
// the fallback. Driven end to end like messages-direct-fireworks.test.mjs: the
// real server against a fake horse-power, a fake OpenAI and a fake OpenRouter.
// What is asserted is the contract — what each upstream was sent, what the
// client got back, what hp is told at settle, and the skip/fail records when
// the request could not ride the direct seam.
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
const WIRE_ECHO = 'gpt-5.5-2026-04-23'; // the dated snapshot OpenAI echoes for a bare request (probed 2026-10-27)
const SLUG = 'openai/gpt-5.5';
const SAFETY_SECRET = 'safety-test-secret';

/** Fake horse-power: an OpenAI candidate ahead of OpenRouter for gpt-5.5; records the rest. */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  let supportsImageInput = true;
  let hardPin = null;
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, web_search: false, max_tokens_cap: 50,
        // hp #1111: the platform's own OpenAI-family preference, a soft directive.
        provider_directive: hardPin ?? { order: ['openai'], ignore: ['amazon-bedrock'] },
        upstreams: [
          { provider: 'openai', api_style: 'openai-responses', host: 'api.openai.com', path: '/v1/responses', key_ref: 'openai',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: supportsImageInput, context_length: 1050000, tier: 'default' },
          { provider: 'openrouter', api_style: 'openai', host: 'openrouter.ai', path: '/api/v1/chat/completions', key_ref: 'openrouter', upstream_model: SLUG },
        ],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, setImages: (v) => { supportsImageInput = v; }, setHardPin: (v) => { hardPin = v; } };
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
// OpenAI's wire: the dated snapshot on response.created and response.completed,
// usage on the terminal event, cached_tokens a subset of input_tokens.
const OAI_CREATED = { type: 'response.created', sequence_number: 0, response: { id: 'resp_oai1', object: 'response', model: WIRE_ECHO, status: 'in_progress', usage: null } };
const DELTAS = [
  { type: 'response.output_item.added', output_index: 0, item: { type: 'message', role: 'assistant', content: [] } },
  { type: 'response.output_text.delta', output_index: 0, delta: 'OK' },
];
const OAI_END = [
  { type: 'response.completed', response: { id: 'resp_oai1', object: 'response', model: WIRE_ECHO, status: 'completed', usage: { input_tokens: 12, output_tokens: 3, total_tokens: 15, input_tokens_details: { cached_tokens: 4 }, output_tokens_details: { reasoning_tokens: 1 } } } },
];
// OpenRouter's relay of the same: public slug, `gen-` id, a cost.
const OR_CREATED = { type: 'response.created', sequence_number: 0, response: { id: 'gen-1790000000-r1', object: 'response', model: SLUG, status: 'in_progress', usage: null } };
const OR_END = [
  { type: 'response.completed', response: { id: 'gen-1790000000-r1', object: 'response', model: SLUG, status: 'completed', usage: { input_tokens: 12, output_tokens: 3, total_tokens: 15, input_tokens_details: { cached_tokens: 4 }, output_tokens_details: { reasoning_tokens: 1 }, cost: 0.00021 } } },
];

/** Fake OpenAI: `/v1/responses` streams an answer or a refused status; any other path is a 404. */
function fakeOpenAI({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/v1/responses') { res.writeHead(404); return res.end(); }
    if (mode === 'status500') {
      res.writeHead(500, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: 'The server had an error', type: 'server_error' } }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(OAI_CREATED));
    for (const d of DELTAS) res.write(sse(d));
    for (const e of OAI_END) res.write(sse(e));
    res.end();
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

/** Fake OpenRouter `/api/v1/responses`: the fallback, always a clean streamed answer (or JSON when asked). */
function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/api/v1/responses') { res.writeHead(404); return res.end(); }
    if (body.stream !== true) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'gen-1790000000-j1', object: 'response', model: SLUG, status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'OK' }] }], usage: { input_tokens: 12, output_tokens: 2, total_tokens: 14, cost: 0.00019 } }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(OR_CREATED));
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

const REQ = (extra = {}) => ({ model: SLUG, max_output_tokens: 200, stream: true, input: 'Say OK.', reasoning: { effort: 'low' }, ...extra });

test('/v1/responses: an OpenAI candidate serves the dialect direct as a pass-through, OpenRouter stays the fallback (horse-power #1156)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'responses-direct-'));
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
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(oai.server, oaiPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENAI_PORT: String(oaiPort), OPENAI_API_KEY: 'openai-test-key',
      OPENROUTER_API_KEY: 'or-test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      SAFETY_IDENTIFIER_SECRET: SAFETY_SECRET,
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. Served direct: OpenAI got the pass-through body with the enclave's
    // OpenAI key and OUR safety identifier; the client got OpenAI's frames with
    // the dated snapshot rewritten to the public slug; hp was told to price the
    // counts against the openai row, the raw echo beside them.
    const direct = await post(inboundPort, '/v1/responses', REQ({ user: 'attacker-chosen', safety_identifier: 'attacker-chosen', temperature: 0.2 }), { 'x-request-id': 'req-direct' });
    assert.equal(direct.status, 200, direct.body);
    assert.match(direct.headers['content-type'], /text\/event-stream/);
    const expected = [OAI_CREATED, ...DELTAS, ...OAI_END].map(sse).join('').replaceAll(`"model":"${WIRE_ECHO}"`, `"model":"${SLUG}"`);
    assert.equal(direct.body, expected, 'OpenAI’s frames, the dated echo rewritten to the public slug');
    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');
    const sent = oai.seen.find((s) => s.path === '/v1/responses');
    assert.ok(sent, 'the request reached api.openai.com/v1/responses, the candidate’s own path');
    assert.equal(sent.headers.authorization, 'Bearer openai-test-key', 'the OpenAI key, never OpenRouter’s or the caller’s');
    assert.equal(sent.headers['x-session-affinity'], undefined, 'no Fireworks-dialect header on OpenAI');
    assert.equal(sent.body.model, UPSTREAM_ID, 'the projected body names the wire model');
    assert.equal(sent.body.store, false);
    assert.equal(sent.body.stream, true);
    assert.equal(sent.body.max_output_tokens, 50, 'hp’s cap landed before projection');
    assert.deepEqual(sent.body.reasoning, { effort: 'low' });
    assert.equal(sent.body.input, 'Say OK.');
    assert.equal(sent.body.safety_identifier, createHmac('sha256', SAFETY_SECRET).update('credit-under-test').digest('hex'), 'OUR identifier, from the authenticated credit id');
    assert.equal('user' in sent.body, false, 'the caller’s tracking ids are dropped');
    assert.equal('temperature' in sent.body, false, 'sampling params are dropped (the reasoning models 400 on them)');
    assert.equal('provider' in sent.body, false, 'hp’s soft preference is absorbed, never forwarded');
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct'), `the direct settle\n${logs}`);
    assert.equal(settle.endpoint, 'responses');
    assert.equal(settle.provider, 'openai');
    assert.equal(settle.route, 'direct');
    assert.equal(settle.route_bail_reason, 'none');
    assert.equal(settle.direct_provider, 'openai');
    assert.equal(settle.cost_source, 'catalog-tokens');
    assert.equal(settle.total_cost_usd, 0);
    assert.equal(settle.generation_id, '');
    assert.equal(settle.model, SLUG, 'settled under the public slug hp priced');
    assert.equal(settle.upstream_model, UPSTREAM_ID);
    assert.equal(settle.served_model, WIRE_ECHO, 'the raw dated echo, for hp’s tripwire (which accepts one dated tail)');
    assert.equal(settle.upstream_provider, null);
    assert.equal(settle.is_byok, undefined);
    assert.equal(settle.input_tokens, 12);
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.output_tokens, 3);
    assert.equal(settle.reasoning_tokens, 1);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.route?.chosen, 'openai');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-direct'), false, 'a clean direct answer reports nothing');

    // 2. OpenAI refuses: drained, never relayed; OpenRouter serves the same
    // request (on the same key, as BYOK), and the settle says why.
    oai.setMode('status500');
    const fellBack = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-fallback' });
    assert.equal(fellBack.status, 200, fellBack.body);
    assert.equal(fellBack.body, [OR_CREATED, ...DELTAS, ...OR_END].map(sse).join(''), 'OpenRouter’s frames, untouched');
    assert.equal(or.seen.length, 1);
    assert.equal(or.seen[0].headers.authorization, 'Bearer or-test-key');
    // The dialect relays apply only HARD pins to the OpenRouter body (hp #1060); a soft preference is not forwarded here, as before.
    assert.equal('provider' in or.seen[0].body, false);
    const fallbackSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-fallback'), `the fallback settle\n${logs}`);
    assert.equal(fallbackSettle.provider, 'openrouter');
    assert.equal(fallbackSettle.route, 'openrouter');
    assert.equal(fallbackSettle.route_bail_reason, 'attempt_failed');
    assert.equal(fallbackSettle.cost_source, 'responses-usage');
    assert.equal(fallbackSettle.total_cost_usd, 0.00021);
    assert.deepEqual(fallbackSettle.trace?.route?.failed?.map((f) => [f.provider, f.status]), [['openai', 500]]);
    oai.setMode('stream');

    // 3. A stateful request (previous_response_id) cannot ride the pass-through
    // (store is always false): skipped by the gate, served by OpenRouter.
    const stateful = await post(inboundPort, '/v1/responses', REQ({ previous_response_id: 'resp_prev' }), { 'x-request-id': 'req-stateful' });
    assert.equal(stateful.status, 200, stateful.body);
    const statefulSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stateful'), `the stateful settle\n${logs}`);
    assert.equal(statefulSettle.provider, 'openrouter');
    assert.equal(statefulSettle.route_bail_reason, 'unsupported_field');
    assert.equal(statefulSettle.route_bail_field, 'previous_response_id');
    assert.equal(oai.seen.length, 2, 'OpenAI saw nothing new');

    // 4. A non-streaming request is a response shape the pass-through does not
    // offer: the projection skips it and OpenRouter answers in JSON.
    const json = await post(inboundPort, '/v1/responses', REQ({ stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    assert.equal(JSON.parse(json.body).model, SLUG);
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.provider, 'openrouter');
    assert.equal(jsonSettle.route_bail_reason, 'stream_required');
    assert.equal(oai.seen.length, 2, 'OpenAI saw nothing new');

    // 5. A web search tool only runs where OpenRouter routes it.
    const searched = await post(inboundPort, '/v1/responses', REQ({ tools: [{ type: 'web_search' }] }), { 'x-request-id': 'req-search' });
    assert.equal(searched.status, 200, searched.body);
    const searchSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-search'), `the search settle\n${logs}`);
    assert.equal(searchSettle.provider, 'openrouter');
    assert.equal(searchSettle.route_bail_reason, 'web_search_requires_openrouter');
    assert.equal(oai.seen.length, 2, 'OpenAI never saw the search tool');

    // 6. A hard provider pin names where OpenRouter must route (hp #1060): the
    // direct candidate is skipped by name.
    hp.setHardPin({ only: ['azure'], allow_fallbacks: false });
    const pinned = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-pinned' });
    assert.equal(pinned.status, 200, pinned.body);
    const pinSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-pinned'), `the pinned settle\n${logs}`);
    assert.equal(pinSettle.provider, 'openrouter');
    assert.equal(pinSettle.route_bail_reason, 'hard_provider_pin');
    assert.deepEqual(or.seen.at(-1).body.provider, { only: ['azure'], allow_fallbacks: false });
    hp.setHardPin(null);

    // 7. An image on a row without vision bails non_text_content; the request
    // rides OpenRouter.
    hp.setImages(false);
    const imaged = await post(inboundPort, '/v1/responses', REQ({ input: [{ role: 'user', content: [{ type: 'input_text', text: 'what is this?' }, { type: 'input_image', image_url: 'data:image/png;base64,QUJD' }] }] }), { 'x-request-id': 'req-image' });
    assert.equal(imaged.status, 200, imaged.body);
    const imageSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-image'), `the image settle\n${logs}`);
    assert.equal(imageSettle.provider, 'openrouter');
    assert.equal(imageSettle.route_bail_reason, 'non_text_content');
    hp.setImages(true);
    assert.equal(oai.seen.length, 2, 'OpenAI saw nothing new');
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, oai.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
