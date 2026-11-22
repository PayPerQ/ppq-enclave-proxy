// #480: on the in-enclave /v1/messages route a Venice candidate is served by
// TRANSLATION — the Messages body becomes a chat-completions request to
// api.venice.ai through the Venice tunnel with the Venice key, shaped by the
// chat path's own Venice rules, and Venice's chat SSE comes back as Anthropic
// SSE. A `venice/*` model is direct-only: there is no OpenRouter fallback, a
// failure is answered by the enclave. Driven end to end like
// messages-direct-openai.test.mjs.
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

const UPSTREAM_ID = 'zai-glm-5.3-flash-uncensored';
const SLUG = 'venice/glm-5-3-flash-uncensored';

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
        upstreams: [
          { provider: 'venice', api_style: 'openai', host: 'api.venice.ai', path: '/api/v1/chat/completions', key_ref: 'venice',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: false, zdr: true },
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

const sse = (ev) => `data: ${typeof ev === 'string' ? ev : JSON.stringify(ev)}\n\n`;
const chunk = (delta, extra = {}) => ({ id: 'chatcmpl-1', object: 'chat.completion.chunk', model: UPSTREAM_ID, choices: [{ index: 0, delta, ...extra }] });
const VENICE_FRAMES = [
  chunk({ role: 'assistant', content: '' }),
  chunk({ content: 'OK' }),
  chunk({ tool_calls: [{ index: 0, id: 'chatcmpl-tool-1', type: 'function', function: { name: 'Bash', arguments: '' } }] }),
  chunk({ tool_calls: [{ index: 0, function: { arguments: '{"command":' } }] }),
  chunk({ tool_calls: [{ index: 0, function: { arguments: '"ls"}' } }] }),
  chunk({}, { finish_reason: 'tool_calls' }),
  { id: 'chatcmpl-1', object: 'chat.completion.chunk', model: UPSTREAM_ID, choices: [], usage: { prompt_tokens: 12, completion_tokens: 3, total_tokens: 15, prompt_tokens_details: { cached_tokens: 4 } } },
  '[DONE]',
];

function fakeVenice({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url !== '/api/v1/chat/completions') { res.writeHead(404); return res.end(); }
    if (mode === 'status500') {
      res.writeHead(500, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Inference failed' }));
    }
    if (body.stream !== true) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        id: 'chatcmpl-2', object: 'chat.completion', model: UPSTREAM_ID,
        choices: [{ index: 0, finish_reason: 'tool_calls', message: { role: 'assistant', content: 'OK', tool_calls: [
          { id: 'chatcmpl-tool-1', type: 'function', function: { name: 'Bash', arguments: '{"command":"ls"}' } },
        ] } }],
        usage: { prompt_tokens: 12, completion_tokens: 3, total_tokens: 15, prompt_tokens_details: { cached_tokens: 4 } },
      }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const f of VENICE_FRAMES) res.write(sse(f));
    res.end();
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    seen.push({ path: req.url });
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `${SLUG} is not a valid model ID` } }));
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
  system: [{ type: 'text', text: 'You are Claude Code.', cache_control: { type: 'ephemeral' } }],
  tools: [{ name: 'Bash', description: 'Run a command', input_schema: { type: 'object', properties: { command: { type: 'string' } } } }],
  thinking: { type: 'enabled', budget_tokens: 4000 },
  metadata: { user_id: 'claude-code-session' },
  messages: [
    { role: 'user', content: 'list files' },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'chatcmpl-tool-0', name: 'Bash', input: { command: 'pwd' } }] },
    { role: 'user', content: [
      { type: 'tool_result', tool_use_id: 'chatcmpl-tool-0', content: '/home' },
      { type: 'text', text: 'now list them' },
    ] },
  ],
  ...extra,
});

test('/v1/messages: a Venice candidate is served direct by translation to its chat wire (#480)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-direct-venice-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.venice.ai',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, venicePort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  const venice = fakeVenice(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(venice.server, venicePort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      VENICE_PORT: String(venicePort), VENICE_API_KEY: 'venice-test-key',
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
    assert.equal(got[0].data.message.model, SLUG, 'the wire id is rewritten to the public slug for the client');
    assert.equal(got[2].data.delta.text, 'OK');
    assert.deepEqual(got[4].data.content_block, { type: 'tool_use', id: 'chatcmpl-tool-1', name: 'Bash', input: {} });
    assert.equal(got[5].data.delta.partial_json + got[6].data.delta.partial_json, '{"command":"ls"}');
    assert.equal(got[8].data.delta.stop_reason, 'tool_use');
    assert.deepEqual(got[8].data.usage, { input_tokens: 8, output_tokens: 3, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 });
    assert.equal(or.seen.length, 0, 'OpenRouter was never asked');

    const sent = venice.seen.at(-1);
    assert.equal(sent.path, '/api/v1/chat/completions');
    assert.equal(sent.headers.authorization, 'Bearer venice-test-key');
    assert.equal(sent.headers['anthropic-version'], undefined, 'the Messages dialect’s headers do not ride to a translated upstream');
    assert.equal(sent.body.model, UPSTREAM_ID);
    assert.equal(sent.body.stream, true);
    assert.deepEqual(sent.body.stream_options, { include_usage: true });
    assert.equal(sent.body.max_tokens, 50, 'hp’s cap landed before translation');
    assert.deepEqual(sent.body.venice_parameters, { include_venice_system_prompt: false }, 'Venice’s own system prompt is off, as on the chat route');
    assert.deepEqual(sent.body.messages, [
      { role: 'system', content: 'You are Claude Code.' },
      { role: 'user', content: 'list files' },
      { role: 'assistant', content: null, tool_calls: [{ id: 'chatcmpl-tool-0', type: 'function', function: { name: 'Bash', arguments: '{"command":"pwd"}' } }] },
      { role: 'tool', tool_call_id: 'chatcmpl-tool-0', content: '/home' },
      { role: 'user', content: 'now list them' },
    ]);
    assert.deepEqual(sent.body.tools, [{ type: 'function', function: { name: 'Bash', description: 'Run a command', parameters: { type: 'object', properties: { command: { type: 'string' } } } } }]);
    for (const k of ['system', 'thinking', 'metadata', 'max_output_tokens']) assert.equal(k in sent.body, false, k);

    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct'), `the direct settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.provider, 'venice');
    assert.equal(settle.route, 'direct');
    assert.equal(settle.direct_provider, 'venice');
    assert.equal(settle.model, SLUG);
    assert.equal(settle.upstream_model, UPSTREAM_ID);
    assert.equal(settle.served_model, UPSTREAM_ID, 'the raw wire echo, for hp’s tripwire');
    assert.equal(settle.input_tokens, 8);
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.output_tokens, 3);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.route?.chosen, 'venice');
    assert.equal(settle.trace?.stream_end, 'clean');

    // 2. Non-streaming: one Message from the one chat.completion.
    const json = await post(inboundPort, '/v1/messages', REQ({ stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    const message = JSON.parse(json.body);
    assert.equal(message.type, 'message');
    assert.equal(message.model, SLUG);
    assert.deepEqual(message.content, [{ type: 'text', text: 'OK' }, { type: 'tool_use', id: 'chatcmpl-tool-1', name: 'Bash', input: { command: 'ls' } }]);
    assert.equal(message.stop_reason, 'tool_use');
    assert.equal(venice.seen.at(-1).body.stream, false);
    assert.equal('stream_options' in venice.seen.at(-1).body, false);
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.provider, 'venice');
    assert.equal(jsonSettle.input_tokens, 8);
    assert.equal(jsonSettle.output_tokens, 3);

    // 3. Venice fails: a direct-only model is answered by the enclave, never
    // handed to OpenRouter (which has never heard of a venice/* id).
    venice.setMode('status500');
    const failed = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-fail' });
    assert.equal(failed.status, 503, failed.body);
    assert.equal(JSON.parse(failed.body).error.type, 'api_error');
    assert.match(JSON.parse(failed.body).error.message, /temporarily unavailable/);
    assert.equal(or.seen.length, 0, 'still never OpenRouter');
    venice.setMode('stream');

    // 4. A shape the chat wire cannot carry: a 400 that names it, sent nowhere.
    const before = venice.seen.length;
    const unmappable = await post(inboundPort, '/v1/messages', REQ({ output_config: { format: { type: 'json_schema', schema: {} } } }), { 'x-request-id': 'req-unmappable' });
    assert.equal(unmappable.status, 400, unmappable.body);
    assert.match(JSON.parse(unmappable.body).error.message, /output_config\.format/);
    assert.equal(venice.seen.length, before, 'never sent');
    assert.equal(or.seen.length, 0);

    // 5. Claude Code's first turn: a system entry inside messages[] (#493).
    const withSystem = await post(inboundPort, '/v1/messages', REQ({
      messages: [
        { role: 'user', content: [{ type: 'text', text: 'list files' }] },
        { role: 'system', content: [{ type: 'text', text: '# Environment\ncwd: /work' }] },
      ],
    }), { 'x-request-id': 'req-system-role' });
    assert.equal(withSystem.status, 200, withSystem.body);
    assert.deepEqual(venice.seen.at(-1).body.messages, [
      { role: 'system', content: 'You are Claude Code.' },
      { role: 'user', content: 'list files' },
      { role: 'system', content: '# Environment\ncwd: /work' },
    ]);
    assert.equal(or.seen.length, 0);
  } finally {
    child.kill('SIGKILL');
    await Promise.all([hp.server, or.server, venice.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
