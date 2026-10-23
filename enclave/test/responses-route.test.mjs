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
      // `ppq/free` is hp's free alias (is_free + the `:online` directive);
      // `openrouter/free` is answered WITHOUT is_free, the resolution-failure
      // shape the enclave must refuse; a `-notools` model carries strip_tools.
      const isFree = body.model === 'ppq/free';
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: isFree, web_search: isFree, max_tokens_cap: 50,
        strip_tools: /-notools$/.test(body.model),
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
// A tool-first answer: the function_call item, then its arguments after a pause.
const TOOL_ANNOUNCE = { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'get_weather', arguments: '' } };
const TOOL_ARGS = [
  { type: 'response.function_call_arguments.delta', output_index: 0, item_id: 'fc_1', delta: '{"city":"Lisbon"}' },
  { type: 'response.function_call_arguments.done', output_index: 0, item_id: 'fc_1', arguments: '{"city":"Lisbon"}' },
];
const TOOL_GAP_MS = 250;
const BIG_LINE_CHARS = 4 * 1024 * 1024 + 4096;
const NOEND_LINE_CHARS = 3 * 1024 * 1024; // 6 MiB on the wire, well past the 4 MiB cap
/** Parse a client-side SSE body into [{event, data}] the way EventSource would. */
function sseEvents(body) {
  return body.split('\n\n').filter((b) => b.length > 0).map((block) => {
    const ev = { event: 'message', data: [] };
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) ev.event = line.slice(6).trim();
      else if (line.startsWith('data:')) ev.data.push(line.slice(5).trimStart());
    }
    return { event: ev.event, data: ev.data.join('\n') };
  });
}
const END = [
  { type: 'response.completed', response: { id: 'gen-1790000000-r1', object: 'response', model: 'openai/gpt-5.5', status: 'completed', usage: { input_tokens: 12, output_tokens: 3, total_tokens: 15, input_tokens_details: { cached_tokens: 4 }, output_tokens_details: { reasoning_tokens: 1 }, cost: 0.00021 } } },
];

/** Fake OpenRouter `/api/v1/responses`: answers per the current mode and records what it was sent. */
// Just over the relay's usage buffer (MAX_RESPONSE_BYTES, 4 MiB).
const HUGE_TEXT = 'The quick brown fox jumps over the lazy dog. '.repeat(100_000);
const HUGE_JSON = JSON.stringify({ id: 'gen-1790000000-huge', object: 'response', model: 'openai/gpt-5.5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: HUGE_TEXT }] }], usage: { input_tokens: 12, output_tokens: 2, total_tokens: 14, cost: 0.00019 } });

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
    if (mode === 'json-huge') {
      // A complete, priced JSON answer over the relay's 4 MiB usage buffer
      // (Oct 17-19 security reports, daff h); its tail usage block says 2 tokens.
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(HUGE_JSON);
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse(CREATED));
    if (mode === 'stream-tool') {
      res.write(sse(TOOL_ANNOUNCE));
      await new Promise((r) => setTimeout(r, TOOL_GAP_MS));
      for (const d of TOOL_ARGS) res.write(sse(d));
      for (const e of END) res.write(sse(e));
      return res.end();
    }
    for (const d of DELTAS) res.write(sse(d));
    if (mode === 'bigline') {
      // One SSE data line past the relay's line cap (d.maxResponseBytes, 4 MiB):
      // GHSA-33j5-hgc8-9mgg F-03. Written in pieces, as a real upstream would.
      // Multi-byte text: the cap is on bytes, and 'é' is two of them.
      const big = sse({ type: 'response.output_text.delta', output_index: 0, delta: 'é'.repeat(BIG_LINE_CHARS / 2) });
      // The terminal frame rides in the same write as the line's tail, so it
      // can share a chunk with the oversized line on the enclave side.
      const tail = big.slice(big.length - 1024) + END.map(sse).join('');
      for (let i = 0; i < big.length - 1024; i += 65536) res.write(big.slice(i, Math.min(i + 65536, big.length - 1024)));
      res.write(tail);
      return res.end();
    }
    if (mode === 'bigline-noend') {
      // The line never ends: no newline, no terminal frame, the upstream just
      // closes. The cap must trip on the bytes accumulated across chunks
      // (CodeRabbit on #360: a reset of the byte count on a newline-less
      // chunk let this grow unbounded).
      const open = `data: {"type":"response.output_text.delta","output_index":0,"delta":"${'é'.repeat(NOEND_LINE_CHARS)}`;
      for (let i = 0; i < open.length; i += 65536) res.write(open.slice(i, i + 65536));
      return res.end();
    }
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

/** Like post(), but the body goes out as given (for a malformed one). */
function postRaw(port, path, payload, headers = {}) {
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
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
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
    assert.ok('upstream_provider' in settle, 'the key is always sent');
    assert.equal(settle.upstream_provider, null, 'Responses reports no sub-provider without the metadata opt-in (#2892)');
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
    assert.equal(settle.trace?.first_token_kind, 'content', 'the first output_text.delta is the first token');
    assert.ok(Number.isInteger(settle.trace?.t_first_content_ms), 'and its timing is recorded');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-stream'), false);

    // 1a. A tool-first answer: the function_call announcement is the first token, not its arguments.
    up.setMode('stream-tool');
    const tool = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-tool' });
    assert.equal(tool.status, 200, tool.body);
    assert.equal(tool.body, [CREATED, TOOL_ANNOUNCE, ...TOOL_ARGS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const toolSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-tool'), `the tool settle\n${logs}`);
    assert.equal(toolSettle.trace?.first_token_kind, 'tool_call');
    assert.ok(
      toolSettle.trace.t_total_ms - toolSettle.trace.t_first_content_ms >= TOOL_GAP_MS - 20,
      `marked on the announcement, not the arguments: ${JSON.stringify(toolSettle.trace)}`,
    );
    up.setMode('stream');

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

    // 2a. A JSON answer over the 4 MiB usage buffer (Oct 17-19 security
    // reports, daff h): delivered whole, and billed from the byte tally,
    // flagged as an estimate and reported; before the fix it settled output 0.
    assert.ok(Buffer.byteLength(HUGE_JSON) > 4 * 1024 * 1024, 'the fixture is over the buffer');
    up.setMode('json-huge');
    const huge = await post(inboundPort, '/v1/responses', REQ({ stream: false }), { 'x-request-id': 'req-json-huge' });
    assert.equal(huge.status, 200);
    assert.equal(huge.body.length, HUGE_JSON.length, 'the oversized answer still reaches the client whole');
    const hugeSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json-huge'), `the huge json settle\n${logs}`);
    assert.equal(hugeSettle.usage_source, 'counted');
    assert.equal(hugeSettle.output_tokens, Math.ceil(Buffer.byteLength(HUGE_JSON) / 4));
    assert.ok(hugeSettle.output_tokens > 1_000_000, hugeSettle.output_tokens);
    assert.equal(hugeSettle.input_tokens > 0, true);
    assert.equal(hugeSettle.total_cost_usd, 0, 'the unread usage block’s cost is not invented: hp prices the tokens');
    const hugeReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-json-huge'), `the huge json usage-missing report\n${logs}`);
    assert.equal(hugeReport.code, 'responses_usage_missing');
    assert.equal(hugeReport.terminal, false);
    assert.equal(jsonSettle.usage_source, 'upstream', 'control: the under-cap answer settles from its usage block');

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

    // 7. Free-model guards (Oct 17-19 security reports). A free credential's paid
    // tools are stripped before the body reaches the upstream, hp's `:online`
    // directive injects nothing, and the settle still says is_free_model.
    up.setMode('stream');
    const PAID_TOOLS = { tools: [{ type: 'web_search_preview' }, { type: 'openrouter:web_search' }, { type: 'function', name: 'f', parameters: {} }], tool_choice: { type: 'web_search_preview' }, plugins: [{ id: 'web' }] };
    const free = await post(inboundPort, '/v1/responses', REQ({ model: 'ppq/free', ...PAID_TOOLS }), { 'x-request-id': 'req-free' });
    assert.equal(free.status, 200, free.body);
    const freeSent = up.seen.filter((s) => s.path === '/api/v1/responses').at(-1);
    assert.equal(freeSent.body.model, 'ppq/free');
    assert.equal('plugins' in freeSent.body, false, 'the web plugin never reaches OpenRouter on a $0 settle');
    assert.deepEqual(freeSent.body.tools, [{ type: 'function', name: 'f', parameters: {} }], 'every web search tool is stripped, the function tool stays');
    assert.equal('tool_choice' in freeSent.body, false, 'the choice named the stripped tool');
    const freeSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-free'), `the free settle\n${logs}`);
    assert.equal(freeSettle.is_free_model, true);
    assert.equal(freeSettle.is_online, false, 'no search was asked of the upstream');
    assert.equal(freeSettle.web_search_engine, undefined, 'nothing left to search with (horse-power #1088)');
    assert.equal(freeSettle.is_byok, false, 'the stream reported OpenRouter’s cost');
    // A paid model with the same tools is forwarded as sent (the control).
    const paid = await post(inboundPort, '/v1/responses', REQ(PAID_TOOLS), { 'x-request-id': 'req-paid-tools' });
    assert.equal(paid.status, 200, paid.body);
    const paidSent = up.seen.filter((s) => s.path === '/api/v1/responses').at(-1);
    assert.equal(paidSent.body.tools.length, 3, 'a paid request keeps its tools');
    assert.deepEqual(paidSent.body.plugins, [{ id: 'web' }]);
    const paidSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-paid-tools'), `the paid settle\n${logs}`);
    assert.equal(paidSettle.is_online, true);
    assert.equal(paidSettle.web_search_engine, 'native', 'a caller’s engine-less plugin is not Exa (horse-power #1088)');
    assert.equal(paidSettle.is_byok, false);
    // A free alias hp did not mark is_free (resolution failure) is refused, not served on the paid path.
    const unauthorizedFree = await post(inboundPort, '/v1/responses', REQ({ model: 'openrouter/free', ...PAID_TOOLS }), { 'x-request-id': 'req-free-unauth' });
    assert.equal(unauthorizedFree.status, 400, unauthorizedFree.body);
    assert.deepEqual(JSON.parse(unauthorizedFree.body), { error: { message: 'free model unavailable on this path', type: 'invalid_request_error', code: 400 } });
    const unauthReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-free-unauth'), `the free refusal report\n${logs}`);
    assert.equal(unauthReport.code, 'free_model_unauthorized');
    assert.equal(up.seen.filter((s) => s.path === '/api/v1/responses').at(-1), paidSent, 'nothing was sent upstream for the refused request');
    // hp's strip_tools directive lands in the Responses shape.
    const stripped = await post(inboundPort, '/v1/responses', REQ({ model: 'some/model-notools', tools: [{ type: 'function', name: 'f' }], tool_choice: 'auto' }), { 'x-request-id': 'req-notools' });
    assert.equal(stripped.status, 200, stripped.body);
    const strippedSent = up.seen.filter((s) => s.path === '/api/v1/responses').at(-1);
    assert.equal('tools' in strippedSent.body, false, 'strip_tools removes the tools');
    assert.equal('tool_choice' in strippedSent.body, false);

    // 6. The relay's own refusals, in the OpenAI shape, on both spellings of the path.
    const bad = await post(inboundPort, '/responses', { model: 'openai/gpt-5.5' });
    assert.equal(bad.status, 400);
    assert.deepEqual(JSON.parse(bad.body), { error: { message: 'input: Field required (a string or an array of input items)', type: 'invalid_request_error', code: 400 } });
    const noCred = await post(inboundPort, '/v1/responses', REQ(), { 'x-api-key': '' });
    assert.equal(noCred.status, 401);
    assert.equal(JSON.parse(noCred.body).error.type, 'authentication_error');
    // A private/* model never leaves this relay for OpenRouter, whatever hp
    // answered and however the prefix is cased (Oct 17-19 security reports).
    const upstreamCallsBefore = up.seen.length;
    const priv = await post(inboundPort, '/v1/responses', REQ({ model: 'Private/glm-5-3' }), { 'x-request-id': 'req-private' });
    assert.equal(priv.status, 400, priv.body);
    const privBody = JSON.parse(priv.body);
    assert.equal(privBody.error.type, 'invalid_request_error');
    assert.match(privBody.error.message, /private\/\* model and is not served on \/v1\/responses/);
    const privReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-private'), `the private refusal report\n${logs}`);
    assert.equal(privReport.code, 'model_rejected_private_path');
    assert.equal(privReport.terminal, true);
    assert.equal(up.seen.length, upstreamCallsBefore, 'no private body reached the upstream');

    // 9. GHSA-33j5-hgc8-9mgg F-01 (andzis): a body that does not parse is refused
    // with a constant message. V8's SyntaxError quotes the text it choked on,
    // and that used to be echoed to the client (unsealed, for an EHBP body).
    // Same rule on every route that parses a body: chat, decisions, the two
    // dialects' relay, count_tokens.
    const SECRET_FRAGMENT = 'zqv-sealed-fragment-7731';
    const malformed = `{"model":"openai/gpt-5.5","input":"${SECRET_FRAGMENT}" "unterminated`;
    for (const [path, shape] of [
      ['/v1/responses', 'dialect'], ['/v1/messages', 'dialect'], ['/v1/messages/count_tokens', 'dialect'],
      ['/v1/chat/completions', 'json'], ['/v1/decisions', 'json'],
    ]) {
      const bad = await postRaw(inboundPort, path, malformed, { 'x-request-id': `req-malformed-${path.replaceAll('/', '_')}` });
      assert.equal(bad.status, 400, `${path}: ${bad.body}`);
      const parsed = JSON.parse(bad.body);
      assert.equal(parsed.error.message, 'request body is not valid JSON', `${path}: ${bad.body}`);
      assert.equal(bad.body.includes(SECRET_FRAGMENT), false, `${path} echoed the body: ${bad.body}`);
      assert.equal(/token|position|Unexpected|JSON at/i.test(bad.body), false, `${path} echoed a parser detail: ${bad.body}`);
      if (shape === 'dialect') assert.equal(parsed.error.type, 'invalid_request_error');
    }
    const malformedReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-malformed-_v1_responses'), `the malformed-body report\n${logs}`);
    assert.equal(malformedReport.code, 'request_unreadable');

    // 10. GHSA-33j5-hgc8-9mgg F-03 (andzis): one SSE line past the relay's cap
    // (4 MiB on the wire) fails the answer in-band, as a cut stream does,
    // instead of being held in memory until its newline. The client's open
    // `data:` line is closed so the error event parses; the terminal frame
    // that follows the oversized line upstream is still read by the pump, so
    // the stream_failed settle bills from the upstream's usage block.
    up.setMode('bigline');
    const big = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-bigline' });
    assert.equal(big.status, 200);
    // The bytes before the cap went out as they arrived (frames are relayed
    // verbatim, chunk by chunk); what the cap stops is the rest of the line,
    // and the heap that holding it would have taken.
    assert.ok(big.body.length < BIG_LINE_CHARS, `the line was cut at the cap, not delivered whole: ${big.body.length} bytes`);
    assert.equal(big.body.includes(sse(END[0])), false, 'nothing after the oversized line is relayed');
    assert.ok(big.body.startsWith([CREATED, ...DELTAS].map(sse).join('')), 'the frames before it went through verbatim');
    assert.ok(big.body.endsWith('event: error\ndata: {"type":"error","code":"upstream_error","message":"upstream error"}\n\n'), `a named error event closes the failed stream: ${big.body.slice(-200)}`);
    const bigEvents = sseEvents(big.body);
    const errorEvent = bigEvents.at(-1);
    assert.equal(errorEvent.event, 'error', `the error event is its own frame, not the tail of the open data line: ${JSON.stringify(bigEvents.slice(-2).map((e) => ({ event: e.event, data: e.data.slice(0, 60) })))}`);
    assert.deepEqual(JSON.parse(errorEvent.data), { type: 'error', code: 'upstream_error', message: 'upstream error' });
    assert.ok(Buffer.byteLength(bigEvents.at(-2).data, 'utf8') <= 4 * 1024 * 1024 + 65536, 'the open line was cut at the byte cap');
    const bigSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-bigline'), `the big-line settle\n${logs}`);
    assert.equal(bigSettle.failure_code, 'stream_failed');
    assert.equal(bigSettle.trace?.stream_end, 'upstream_error');
    assert.equal(bigSettle.cost_source, 'responses-usage', 'the terminal frame after the oversized line was read: real usage, not a count');
    assert.equal(bigSettle.output_tokens, 3);
    assert.equal(bigSettle.input_tokens, 12);
    assert.ok(bigSettle.trace?.bytes_out > 0, 'the bytes the client did get are on the settle trace');
    assert.match(logs, /sse line over \d+ bytes; answer failed/);

    // 11. The same cap on a line that never ends (no newline, no terminal
    // frame): the bytes are summed across chunks, the answer fails at the
    // cap, and the settle counts the deltas that were delivered.
    up.setMode('bigline-noend');
    const noend = await post(inboundPort, '/v1/responses', REQ(), { 'x-request-id': 'req-bigline-noend' });
    assert.equal(noend.status, 200);
    assert.ok(noend.body.length < 5 * 1024 * 1024, `cut at the cap, not relayed whole (6 MiB): ${noend.body.length} bytes`);
    const noendEvents = sseEvents(noend.body);
    assert.equal(noendEvents.at(-1).event, 'error', 'the error event is its own frame after the open line');
    assert.deepEqual(JSON.parse(noendEvents.at(-1).data), { type: 'error', code: 'upstream_error', message: 'upstream error' });
    const openBytes = Buffer.byteLength(noendEvents.at(-2).data, 'utf8');
    assert.ok(openBytes > 4 * 1024 * 1024 - 65536 && openBytes <= 4 * 1024 * 1024 + 65536, `the open line stopped at the byte cap: ${openBytes}`);
    const noendSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-bigline-noend'), `the no-end settle\n${logs}`);
    assert.equal(noendSettle.failure_code, 'stream_failed');
    assert.equal(noendSettle.usage_source, 'counted', 'no terminal frame: settled from the delivered deltas');
    assert.ok(noendSettle.output_tokens >= 1 && noendSettle.output_tokens <= 4, `counted "OK then": ${noendSettle.output_tokens}`);
    assert.ok(noendSettle.input_tokens > 0);
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
