// horse-power #1156: on the in-enclave /v1/messages route an OpenAI candidate
// hp offers is tried FIRST, by TRANSLATION — the Messages body becomes a
// Responses request to api.openai.com/v1/responses through the OpenAI tunnel
// with the OpenAI key, and OpenAI's SSE comes back as Anthropic SSE; OpenRouter
// stays the fallback. Driven end to end like messages-direct-fireworks.test.mjs.
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

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const evt = (ev) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;
// OpenAI's Responses wire for a one-line answer, with a tool call.
const OAI_FRAMES = [
  { type: 'response.created', response: { id: 'resp_1', model: WIRE_ECHO, status: 'in_progress', usage: null } },
  { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', content: [] } },
  { type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, delta: 'OK' },
  { type: 'response.output_item.done', output_index: 0, item: { type: 'message', id: 'msg_1' } },
  { type: 'response.output_item.added', output_index: 1, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'Bash', arguments: '' } },
  { type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 1, delta: '{"command":' },
  { type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 1, delta: '"ls"}' },
  { type: 'response.function_call_arguments.done', item_id: 'fc_1', output_index: 1, arguments: '{"command":"ls"}' },
  { type: 'response.output_item.done', output_index: 1, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'Bash', arguments: '{"command":"ls"}' } },
  { type: 'response.completed', response: { id: 'resp_1', model: WIRE_ECHO, status: 'completed', usage: { input_tokens: 12, output_tokens: 3, total_tokens: 15, input_tokens_details: { cached_tokens: 4 }, output_tokens_details: { reasoning_tokens: 1 } } } },
];
// OpenRouter's Messages relay of the same request.
const OR_START = { type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model: SLUG, provider: 'OpenAI', stop_reason: null, usage: { input_tokens: 8, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } } };
const OR_END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];
const OR_DELTAS = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_stop', index: 0 },
];

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
    if (mode === 'truncated') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(evt(OAI_FRAMES[0]));
      res.write(evt(OAI_FRAMES[2]));
      return res.end(); // no response.completed
    }
    if (body.stream !== true) {
      // The non-streaming answer: one Responses object (horse-power #1159).
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'resp_1', object: 'response', model: WIRE_ECHO, status: 'completed', output: [
        { type: 'message', id: 'msg_1', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'OK', annotations: [] }] },
        OAI_FRAMES[8].item,
      ], usage: OAI_FRAMES.at(-1).response.usage }));
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
    if (req.url !== '/api/v1/messages') { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(OR_START));
    for (const d of OR_DELTAS) res.write(sse(d));
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

/** Parse an Anthropic SSE body into [{event, data}]. */
const events = (body) => body.split('\n\n').filter(Boolean).map((block) => {
  const lines = block.split('\n');
  const ev = lines.find((l) => l.startsWith('event:'))?.slice(6).trim();
  const data = lines.find((l) => l.startsWith('data:'))?.slice(5).trim();
  return { event: ev, data: data ? JSON.parse(data) : undefined };
});

const REQ = (extra = {}) => ({
  model: SLUG, max_tokens: 200, stream: true,
  system: 'You are Claude Code.',
  tools: [{ name: 'Bash', description: 'Run a command', input_schema: { type: 'object', properties: { command: { type: 'string' } } } }],
  messages: [{ role: 'user', content: 'list files' }],
  metadata: { user_id: 'attacker-chosen' },
  ...extra,
});

test('/v1/messages: an OpenAI candidate is served direct by translation, OpenRouter stays the fallback (horse-power #1156)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-direct-openai-'));
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

    // 1. Served direct by translation.
    const direct = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-direct' });
    assert.equal(direct.status, 200, direct.body);
    assert.match(direct.headers['content-type'], /text\/event-stream/);
    const got = events(direct.body);
    assert.deepEqual(got.map((e) => e.event), [
      'message_start', 'content_block_start', 'content_block_delta', 'content_block_stop',
      'content_block_start', 'content_block_delta', 'content_block_delta', 'content_block_stop',
      'message_delta', 'message_stop',
    ], direct.body);
    assert.equal(got[0].data.message.model, SLUG, 'the dated snapshot echo is rewritten to the public slug for the client');
    assert.equal(got[2].data.delta.text, 'OK');
    assert.deepEqual(got[4].data.content_block, { type: 'tool_use', id: 'call_1', name: 'Bash', input: {} });
    assert.equal(got[5].data.delta.partial_json + got[6].data.delta.partial_json, '{"command":"ls"}');
    assert.deepEqual(got[8].data.usage, { input_tokens: 8, output_tokens: 3, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 }, 'additive convention: input excludes the cache bucket');
    assert.equal(got[8].data.delta.stop_reason, 'tool_use');
    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');

    const sent = oai.seen.find((s) => s.path === '/v1/responses');
    assert.ok(sent, 'the translated request reached api.openai.com/v1/responses');
    assert.equal(sent.headers.authorization, 'Bearer openai-test-key');
    assert.equal(sent.headers['anthropic-version'], undefined, 'the Messages dialect’s headers do not ride to a translated upstream');
    assert.equal(sent.body.model, UPSTREAM_ID);
    assert.equal(sent.body.store, false);
    assert.equal(sent.body.stream, true);
    assert.equal(sent.body.max_output_tokens, 50, 'hp’s cap (on max_tokens) landed before translation');
    assert.deepEqual(sent.body.input[0], { role: 'system', content: [{ type: 'input_text', text: 'You are Claude Code.' }] });
    assert.deepEqual(sent.body.input[1], { role: 'user', content: [{ type: 'input_text', text: 'list files' }] });
    assert.equal(sent.body.tools[0].type, 'function');
    assert.equal(sent.body.tools[0].name, 'Bash');
    assert.equal(sent.body.safety_identifier, createHmac('sha256', SAFETY_SECRET).update('credit-under-test').digest('hex'), 'OUR identifier');
    assert.equal('metadata' in sent.body, false, 'the caller’s user_id is dropped');
    assert.equal('messages' in sent.body, false);

    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct'), `the direct settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.provider, 'openai');
    assert.equal(settle.route, 'direct');
    assert.equal(settle.direct_provider, 'openai');
    assert.equal(settle.cost_source, 'catalog-tokens');
    assert.equal(settle.total_cost_usd, 0);
    assert.equal(settle.model, SLUG);
    assert.equal(settle.upstream_model, UPSTREAM_ID);
    assert.equal(settle.served_model, WIRE_ECHO, 'the raw dated echo from message_start, for hp’s tripwire');
    assert.equal(settle.input_tokens, 8, 'additive: hp folds cache_read back in');
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.output_tokens, 3);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.route?.chosen, 'openai');
    assert.equal(settle.trace?.stream_end, 'clean');

    // 2. OpenAI refuses: OpenRouter serves the Messages request as before.
    oai.setMode('status500');
    const fellBack = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-fallback' });
    assert.equal(fellBack.status, 200, fellBack.body);
    assert.equal(fellBack.body, [OR_START, ...OR_DELTAS, ...OR_END].map(sse).join(''), 'OpenRouter’s frames, untouched');
    assert.equal(or.seen.length, 1);
    assert.equal(or.seen[0].headers['anthropic-version'], '2023-06-01', 'the dialect header rides to OpenRouter');
    const fallbackSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-fallback'), `the fallback settle\n${logs}`);
    assert.equal(fallbackSettle.provider, 'openrouter');
    assert.equal(fallbackSettle.route_bail_reason, 'attempt_failed');
    assert.deepEqual(fallbackSettle.trace?.route?.failed?.map((f) => [f.provider, f.status]), [['openai', 500]]);

    // 3. A stream that dies before response.completed ends as a terminal
    // Anthropic error event (the translation's finish() rides the same pump);
    // with no usage frame the settle bills what actually went out, counted.
    oai.setMode('truncated');
    const cut = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-cut' });
    assert.equal(cut.status, 200, cut.body);
    const cutEvents = events(cut.body);
    assert.equal(cutEvents.at(-1).event, 'error', cut.body);
    assert.match(cutEvents.at(-1).data.error.message, /ended unexpectedly/);
    const cutSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-cut'), `the cut settle\n${logs}`);
    assert.equal(cutSettle.provider, 'openai');
    assert.equal(cutSettle.usage_source, 'counted');
    assert.ok(cutSettle.output_tokens >= 1, 'the translated "OK" that reached the client is billed');
    oai.setMode('stream');

    // 4. What the translation cannot carry skips the candidate, named:
    // stop_sequences has no Responses equivalent.
    const stopped = await post(inboundPort, '/v1/messages', REQ({ stop_sequences: ['END'] }), { 'x-request-id': 'req-stop' });
    assert.equal(stopped.status, 200, stopped.body);
    const stopSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stop'), `the stop settle\n${logs}`);
    assert.equal(stopSettle.provider, 'openrouter');
    assert.equal(stopSettle.route_bail_reason, 'unmappable_field');
    assert.equal(stopSettle.route_bail_field, 'stop_sequences');

    // 5. A dated Anthropic server tool only runs where OpenRouter routes it.
    const searched = await post(inboundPort, '/v1/messages', REQ({ tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }] }), { 'x-request-id': 'req-search' });
    assert.equal(searched.status, 200, searched.body);
    const searchSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-search'), `the search settle\n${logs}`);
    assert.equal(searchSettle.provider, 'openrouter');
    assert.equal(searchSettle.route_bail_reason, 'web_search_requires_openrouter');
    assert.equal(oai.seen.filter((s) => s.body?.tools?.some((t) => t.type !== 'function')).length, 0);

    // 6. A NON-streaming turn is served direct too (horse-power #1159): one
    // Message, translated from the one Responses object, under the public slug.
    const json = await post(inboundPort, '/v1/messages', REQ({ stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    assert.doesNotMatch(json.headers['content-type'], /text\/event-stream/);
    const message = JSON.parse(json.body);
    assert.equal(message.type, 'message');
    assert.equal(message.model, SLUG);
    assert.deepEqual(message.content, [{ type: 'text', text: 'OK' }, { type: 'tool_use', id: 'call_1', name: 'Bash', input: { command: 'ls' } }]);
    assert.equal(message.stop_reason, 'tool_use');
    assert.deepEqual(message.usage, { input_tokens: 8, output_tokens: 3, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 }, 'additive convention, as on the stream');
    assert.equal(oai.seen.at(-1).body.stream, false, 'the caller’s mode rides the wire');
    assert.equal(oai.seen.at(-1).headers.accept, 'application/json');
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.provider, 'openai');
    assert.equal(jsonSettle.route, 'direct');
    assert.equal(jsonSettle.served_model, WIRE_ECHO);
    assert.equal(jsonSettle.input_tokens, 8, 'additive: hp folds cache_read back in');
    assert.equal(jsonSettle.output_tokens, 3);
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, oai.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
