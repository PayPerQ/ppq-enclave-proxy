// The in-enclave /v1/messages route (#275), driven end to end: the real
// server against a fake horse-power and a fake OpenRouter that speaks the
// Anthropic Messages dialect. What is asserted is the contract: the frames a
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
  // When set, authorize answers this as resolved_model instead of echoing the
  // caller's id: how a lying or confused hp would rewrite a public model.
  let resolvedModelOverride = null;
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      authorizes.push(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      // `ppq/free` is hp's free alias (is_free + the `:online` directive, as
      // a free user with web search on sends it); `openrouter/free` is
      // answered WITHOUT is_free, the resolution-failure shape the enclave
      // must refuse; a `-notools` model carries hp's strip_tools.
      const isFree = body.model === 'ppq/free';
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: resolvedModelOverride ?? body.model, is_free: isFree, web_search: isFree, max_tokens_cap: 50,
        strip_tools: /-notools$/.test(body.model),
        provider_directive: { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice'] },
        upstreams: [{ provider: 'anthropic', api_style: 'anthropic', host: 'localhost', upstream_model: 'claude-sonnet-4-6-20260301' }],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors, authorizes, setResolvedModel: (m) => { resolvedModelOverride = m; } };
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const START = { type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model: 'anthropic/claude-sonnet-4.6', stop_reason: null, usage: { input_tokens: 12, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 0 } } };
// The same opening as OpenRouter sends it for a routed open-weights model: the
// serving sub-provider on the message object (#2892).
const START_ROUTED = { ...START, message: { ...START.message, provider: 'Fireworks' } };
const DELTAS = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ' then' } },
  { type: 'content_block_stop', index: 0 },
];
// A tool-first answer: the tool_use announcement, then its arguments after a pause.
const TOOL_ANNOUNCE = { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'toolu_1', name: 'get_weather', input: {} } };
const TOOL_ARGS = [
  { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"city":"Lisbon"}' } },
  { type: 'content_block_stop', index: 0 },
];
const TOOL_GAP_MS = 250;
const END = [
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];

// Just over the relay's usage buffer (MAX_RESPONSE_BYTES, 4 MiB): a prose
// answer the client receives whole, whose usage block the relay cannot keep.
const HUGE_TEXT = 'The quick brown fox jumps over the lazy dog. '.repeat(100_000);
const HUGE_JSON = JSON.stringify({ id: 'gen-1790000000-huge', type: 'message', role: 'assistant', model: 'anthropic/claude-sonnet-4.6', content: [{ type: 'text', text: HUGE_TEXT }], stop_reason: 'end_turn', usage: { input_tokens: 12, output_tokens: 2, cost: 0.00019 } });

/**
 * Fake OpenRouter `/api/v1/messages` (and, on the same port, Anthropic's
 * count_tokens): answers per the current mode and records what it was sent.
 */
function fakeUpstream({ key, cert }) {
  let mode = 'stream';
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, headers: req.headers, body });
    if (req.url === '/v1/messages/count_tokens') {
      if (req.headers['x-api-key'] !== 'anthropic-test-key') { res.writeHead(401); return res.end('{}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ input_tokens: 42 }));
    }
    if (req.url !== '/api/v1/messages') { res.writeHead(404); return res.end(); }
    if (mode === 'status429') {
      res.writeHead(429, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Rate limited by OpenRouter', metadata: { provider_name: 'Anthropic' } }, user_id: 'org_test00000000000000000000' }));
    }
    if (mode === 'json-unrouted') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'gen-1790000000-j2', type: 'message', role: 'assistant', model: 'anthropic/claude-sonnet-4.6', content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', usage: { input_tokens: 12, output_tokens: 2, cost: 0.00019 } }));
    }
    if (mode === 'json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ id: 'gen-1790000000-j1', type: 'message', role: 'assistant', model: 'anthropic/claude-sonnet-4.6', provider: 'Fireworks', content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', usage: { input_tokens: 12, output_tokens: 2, cost: 0.00019 } }));
    }
    if (mode === 'json-huge') {
      // A complete, priced JSON answer whose body is over the relay's 4 MiB
      // usage buffer (Oct 17-19 security reports, daff h). The usage block
      // at its tail says 2 tokens; the relay must never read it.
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(HUGE_JSON);
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    if (mode === 'stream-tool') {
      res.write(sse(START));
      res.write(sse(TOOL_ANNOUNCE));
      await new Promise((r) => setTimeout(r, TOOL_GAP_MS));
      for (const d of TOOL_ARGS) res.write(sse(d));
      for (const e of END) res.write(sse(e));
      return res.end();
    }
    res.write(sse(mode === 'stream-routed' ? START_ROUTED : START));
    for (const d of DELTAS) res.write(sse(d));
    if (mode === 'cut') return res.end();
    if (mode === 'error-event') {
      res.write(sse({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }));
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

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.fail(`timed out waiting for ${what}`);
}

const REQ = (_requestId, extra = {}) => ({ model: 'anthropic/claude-sonnet-4.6', max_tokens: 200, stream: true, messages: [{ role: 'user', content: 'Say OK.' }], ...extra });

test('/v1/messages is served in-enclave: verbatim frames, a settle hp can price, reports on failure', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'messages-route-'));
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
      // count_tokens goes to "Anthropic" on the same fake, under its own host override.
      ANTHROPIC_HOST: 'localhost', ANTHROPIC_PORT: String(upPort), ANTHROPIC_API_KEY: 'anthropic-test-key',
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. A streamed answer: frames verbatim, max_tokens capped, settle priced from the stream.
    up.setMode('stream');
    const streamed = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-stream', 'anthropic-version': '2023-06-01' });
    assert.equal(streamed.status, 200, streamed.body);
    assert.match(streamed.headers['content-type'], /text\/event-stream/);
    assert.equal(streamed.body, [START, ...DELTAS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const sentUp = up.seen.find((s) => s.path === '/api/v1/messages');
    assert.equal(sentUp.body.max_tokens, 50, 'hp’s max_tokens_cap lands on the field the API requires');
    assert.equal(sentUp.body.stream, true);
    assert.deepEqual(sentUp.body.provider, { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice'] }, 'hp’s hard provider pin rides the verbatim dialect (hp #1060)');
    assert.equal(sentUp.headers['anthropic-version'], '2023-06-01', 'the dialect’s version header rides through');
    assert.equal(sentUp.headers.authorization, 'Bearer test-key', 'the enclave’s key, never the caller’s');
    assert.equal(hp.authorizes.at(-1).endpoint, 'messages');
    assert.ok(hp.authorizes.at(-1).input_tokens_o200k > 0, 'authorize carried the o200k measure');
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stream'), `the stream settle\n${logs}`);
    assert.equal(settle.endpoint, 'messages');
    assert.equal(settle.cost_source, 'messages-usage');
    assert.equal(settle.model, 'anthropic/claude-sonnet-4.6');
    assert.equal(settle.served_model, 'anthropic/claude-sonnet-4.6');
    assert.equal(settle.generation_id, 'gen-1790000000-m1');
    assert.equal(settle.input_tokens, 12);
    assert.equal(settle.output_tokens, 3, 'message_delta’s cumulative count wins over message_start’s 1');
    assert.equal(settle.cache_read_tokens, 4);
    assert.equal(settle.total_cost_usd, 0.00021);
    assert.equal(settle.usage_source, 'upstream');
    assert.equal(settle.trace?.stream_end, 'clean');
    assert.equal(settle.trace?.route?.chosen, 'openrouter');
    assert.equal(settle.trace?.first_token_kind, 'content');
    assert.ok(Number.isInteger(settle.trace?.t_first_content_ms));
    assert.equal(settle.failure_code, undefined);
    assert.equal(settle.provider, 'openrouter');
    assert.ok('upstream_provider' in settle, 'the key is always sent');
    assert.equal(settle.upstream_provider, null, 'no sub-provider reported → null, never guessed');
    assert.equal(hp.errors.some((e) => e.trace?.client_request_id === 'req-stream'), false, 'a clean answer reports nothing');

    // 1a. OpenRouter names its serving sub-provider on message_start.message: it reaches the settle,
    // and the frames still go through untouched (#2892).
    up.setMode('stream-routed');
    const routed = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-routed' });
    assert.equal(routed.status, 200, routed.body);
    assert.equal(routed.body, [START_ROUTED, ...DELTAS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const routedSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-routed'), `the routed settle\n${logs}`);
    assert.equal(routedSettle.provider, 'openrouter');
    assert.equal(routedSettle.upstream_provider, 'Fireworks');

    // 1a'. A tool-first answer: the tool_use announcement is the first token, not its arguments.
    up.setMode('stream-tool');
    const tool = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-tool' });
    assert.equal(tool.status, 200, tool.body);
    assert.equal(tool.body, [START, TOOL_ANNOUNCE, ...TOOL_ARGS, ...END].map(sse).join(''), 'the upstream frames go through untouched');
    const toolSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-tool'), `the tool settle\n${logs}`);
    assert.equal(toolSettle.trace?.first_token_kind, 'tool_call');
    assert.ok(
      toolSettle.trace.t_total_ms - toolSettle.trace.t_first_content_ms >= TOOL_GAP_MS - 20,
      `marked on the announcement, not the arguments: ${JSON.stringify(toolSettle.trace)}`,
    );

    // 1b. The cap keeps thinking.budget_tokens under max_tokens; under the API's minimum, thinking is off.
    up.setMode('stream');
    await post(inboundPort, '/v1/messages', REQ(null, { max_tokens: 8000, thinking: { type: 'enabled', budget_tokens: 6000 } }), { 'x-request-id': 'req-think' });
    const thinkSent = up.seen.filter((s) => s.path === '/api/v1/messages').at(-1);
    assert.equal(thinkSent.body.max_tokens, 50, 'capped');
    assert.deepEqual(thinkSent.body.thinking, { type: 'disabled' }, 'a budget that cannot fit under the cap turns thinking off rather than 400');

    // 2. A JSON (non-streaming) answer: passed through whole, settle from its usage block.
    up.setMode('json');
    const json = await post(inboundPort, '/v1/messages', REQ(null, { stream: false }), { 'x-request-id': 'req-json' });
    assert.equal(json.status, 200, json.body);
    assert.equal(JSON.parse(json.body).content[0].text, 'OK');
    const jsonSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json'), `the json settle\n${logs}`);
    assert.equal(jsonSettle.output_tokens, 2);
    assert.equal(jsonSettle.total_cost_usd, 0.00019);
    assert.equal(jsonSettle.generation_id, 'gen-1790000000-j1');
    assert.equal(jsonSettle.upstream_provider, 'Fireworks', 'the JSON body’s provider reaches the settle (#2892)');
    up.setMode('json-unrouted');
    await post(inboundPort, '/v1/messages', REQ(null, { stream: false }), { 'x-request-id': 'req-json-unrouted' });
    const unroutedSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json-unrouted'), `the unrouted json settle\n${logs}`);
    assert.ok('upstream_provider' in unroutedSettle, 'the key is always sent');
    assert.equal(unroutedSettle.upstream_provider, null, 'no provider on the body → null');
    assert.equal(jsonSettle.trace?.stream_end, 'clean');

    // 2a. A JSON answer over the 4 MiB usage buffer (Oct 17-19 security
    // reports, daff h): delivered whole, and billed. Its usage block was never
    // read and the counter sees stream deltas only, so before the fix the
    // settle said output 0 for a multi-megabyte answer. Now it is priced from
    // the bytes the upstream sent, flagged as an estimate, and reported.
    assert.ok(Buffer.byteLength(HUGE_JSON) > 4 * 1024 * 1024, 'the fixture is over the buffer');
    up.setMode('json-huge');
    const huge = await post(inboundPort, '/v1/messages', REQ(null, { stream: false }), { 'x-request-id': 'req-json-huge' });
    assert.equal(huge.status, 200);
    assert.equal(huge.body.length, HUGE_JSON.length, 'the oversized answer still reaches the client whole');
    const hugeSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-json-huge'), `the huge json settle\n${logs}`);
    assert.equal(hugeSettle.usage_source, 'counted', 'an estimate, never passed off as the upstream’s figure');
    assert.equal(hugeSettle.output_tokens, Math.ceil(Buffer.byteLength(HUGE_JSON) / 4), 'priced from the byte tally at the counter’s overflow ratio');
    assert.ok(hugeSettle.output_tokens > 1_000_000, hugeSettle.output_tokens);
    assert.equal(hugeSettle.input_tokens > 0, true, 'the prompt is billed from the o200k measure');
    assert.equal(hugeSettle.total_cost_usd, 0, 'the unread usage block’s cost is not invented: hp prices the tokens');
    assert.equal(hugeSettle.trace?.stream_end, 'clean');
    const hugeReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-json-huge'), `the huge json usage-missing report\n${logs}`);
    assert.equal(hugeReport.code, 'messages_usage_missing');
    assert.equal(hugeReport.terminal, false, 'reported, not released: the row is billed');
    // Control: the under-cap JSON answer above still settled from its own usage block.
    assert.equal(jsonSettle.usage_source, 'upstream');

    // 3. A refused request: the status passes through, the body is sanitized, nothing settles.
    up.setMode('status429');
    const refused = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-429' });
    assert.equal(refused.status, 429);
    assert.equal(refused.body.includes('org_'), false, `the OpenRouter organisation id must not reach the client: ${refused.body}`);
    assert.equal(/openrouter/i.test(refused.body), false, `the upstream must not be named: ${refused.body}`);
    assert.equal(JSON.parse(refused.body).type, 'error', 'still the dialect’s error shape');
    const report429 = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-429'), `the 429 report\n${logs}`);
    assert.equal(report429.code, 'upstream_error_status');
    assert.equal(report429.upstream_status, 429);
    assert.equal(report429.terminal, true);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-429'), false, 'a refused request never settles');

    // 4. A stream cut before message_stop: the client is told in-band, the settle bills what went out.
    up.setMode('cut');
    const cut = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-cut' });
    assert.equal(cut.status, 200);
    assert.ok(cut.body.endsWith('event: error\ndata: {"type":"error","error":{"type":"api_error","message":"upstream error"}}\n\n'), `an in-band error frame closes a truncated stream: ${cut.body.slice(-200)}`);
    const cutSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-cut'), `the cut settle\n${logs}`);
    assert.equal(cutSettle.failure_code, 'stream_failed');
    assert.equal(cutSettle.trace?.stream_end, 'upstream_error');
    assert.equal(cutSettle.usage_source, 'counted', 'no message_delta came: the delivered deltas are counted');
    assert.ok(cutSettle.output_tokens >= 1 && cutSettle.output_tokens <= 4, `counted "OK then": ${cutSettle.output_tokens}`);
    assert.equal(cutSettle.input_tokens, 12, 'message_start’s input count is kept');
    const cutReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-cut'), `the cut report\n${logs}`);
    assert.equal(cutReport.code, 'stream_failed');
    assert.equal(cutReport.terminal, false);

    // 5. The upstream's own in-band error event: relayed verbatim, settled as an upstream error.
    up.setMode('error-event');
    const errored = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-errev' });
    assert.equal(errored.status, 200);
    assert.ok(errored.body.includes('"overloaded_error"'), 'the upstream’s error event reaches the client as sent');
    assert.equal((errored.body.match(/event: error/g) || []).length, 0, 'no second frame is appended after the upstream’s own');
    const errSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-errev'), `the error-event settle\n${logs}`);
    assert.equal(errSettle.failure_code, 'upstream_error_status');
    assert.equal(errSettle.trace?.stream_end, 'upstream_error');

    // 6. The handler's own refusals are in the dialect.
    const bad = await post(inboundPort, '/v1/messages', { model: 'anthropic/claude-sonnet-4.6', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(bad.status, 400);
    assert.deepEqual(JSON.parse(bad.body), { type: 'error', error: { type: 'invalid_request_error', message: 'max_tokens: Field required (a positive integer)' } });
    const noCred = await post(inboundPort, '/v1/messages', REQ(), { 'x-api-key': '' });
    assert.equal(noCred.status, 401);
    assert.equal(JSON.parse(noCred.body).error.type, 'authentication_error');
    // A private/* model never leaves this relay for OpenRouter, whatever hp
    // answered and however the prefix is cased (Oct 17-19 security reports).
    // The fake hp echoes the caller's model as resolved_model, so both ids
    // the guard judges carry the private prefix here.
    const upstreamCallsBefore = up.seen.length;
    for (const [i, spelling] of ['private/glm-5-3', 'Private/glm-5-3'].entries()) {
      const priv = await post(inboundPort, '/v1/messages', REQ(undefined, { model: spelling }), { 'x-request-id': `req-private-${i}` });
      assert.equal(priv.status, 400, priv.body);
      const privBody = JSON.parse(priv.body);
      assert.equal(privBody.error.type, 'invalid_request_error');
      assert.match(privBody.error.message, /private\/\* model and is not served on \/v1\/messages/);
      const privReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === `req-private-${i}`), `the private refusal report (${spelling})\n${logs}`);
      assert.equal(privReport.code, 'model_rejected_private_path');
      assert.equal(privReport.terminal, true, 'hp releases the hold: nothing settles');
    }
    assert.equal(up.seen.length, upstreamCallsBefore, 'no private body reached the upstream');
    // The second id the guard judges, on its own: a public caller model that hp
    // resolves onto a private/* id. The body is still refused before it leaves.
    hp.setResolvedModel('private/glm-5-3');
    try {
      const resolvedPriv = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': 'req-private-resolved' });
      assert.equal(resolvedPriv.status, 400, resolvedPriv.body);
      const resolvedBody = JSON.parse(resolvedPriv.body);
      assert.equal(resolvedBody.error.type, 'invalid_request_error');
      assert.match(resolvedBody.error.message, /private\/\* model and is not served on \/v1\/messages/);
      const resolvedReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-private-resolved'), `the resolved-private refusal report\n${logs}`);
      assert.equal(resolvedReport.code, 'model_rejected_private_path');
      assert.equal(resolvedReport.terminal, true, 'hp releases the hold: nothing settles');
    } finally {
      hp.setResolvedModel(null);
    }
    assert.equal(up.seen.length, upstreamCallsBefore, 'no body reached the upstream on the resolved-private refusal either');

    // 8. Free-model guards (Oct 17-19 security reports). A free credential's paid
    // tools are stripped before the body reaches the upstream, hp's `:online`
    // directive injects nothing, and the settle still says is_free_model.
    up.setMode('stream');
    const PAID_TOOLS = { tools: [{ type: 'web_search_20250305', name: 'web_search' }, { type: 'openrouter:web_search' }, { name: 'get_weather', input_schema: { type: 'object' } }], tool_choice: { type: 'tool', name: 'web_search' }, plugins: [{ id: 'web' }] };
    const free = await post(inboundPort, '/v1/messages', REQ(null, { model: 'ppq/free', ...PAID_TOOLS }), { 'x-request-id': 'req-free' });
    assert.equal(free.status, 200, free.body);
    const freeSent = up.seen.filter((s) => s.path === '/api/v1/messages').at(-1);
    assert.equal(freeSent.body.model, 'ppq/free');
    assert.equal('plugins' in freeSent.body, false, 'the web plugin never reaches OpenRouter on a $0 settle');
    assert.deepEqual(freeSent.body.tools, [{ name: 'get_weather', input_schema: { type: 'object' } }], 'every web search tool is stripped, the function tool stays');
    assert.equal('tool_choice' in freeSent.body, false, 'the choice named the stripped tool');
    const freeSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-free'), `the free settle\n${logs}`);
    assert.equal(freeSettle.is_free_model, true);
    assert.equal(freeSettle.is_online, false, 'no search was asked of the upstream');
    assert.equal(freeSettle.web_search_engine, undefined, 'nothing left to search with (horse-power #1088)');
    assert.equal(freeSettle.is_byok, false, 'the stream reported OpenRouter’s cost');
    // A paid model with the same tools is forwarded as sent (the control).
    const paid = await post(inboundPort, '/v1/messages', REQ(null, PAID_TOOLS), { 'x-request-id': 'req-paid-tools' });
    assert.equal(paid.status, 200, paid.body);
    const paidSent = up.seen.filter((s) => s.path === '/api/v1/messages').at(-1);
    assert.equal(paidSent.body.tools.length, 3, 'a paid request keeps its tools');
    assert.deepEqual(paidSent.body.plugins, [{ id: 'web' }]);
    const paidSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-paid-tools'), `the paid settle\n${logs}`);
    assert.equal(paidSettle.is_online, true);
    assert.equal(paidSettle.web_search_engine, 'native', 'an engine-less plugin is not Exa; the dated tool is the provider’s (horse-power #1088)');
    assert.equal(paidSettle.is_byok, false);
    // A free alias hp did not mark is_free (resolution failure) is refused, not served on the paid path.
    const unauthorizedFree = await post(inboundPort, '/v1/messages', REQ(null, { model: 'openrouter/free', ...PAID_TOOLS }), { 'x-request-id': 'req-free-unauth' });
    assert.equal(unauthorizedFree.status, 400, unauthorizedFree.body);
    assert.deepEqual(JSON.parse(unauthorizedFree.body), { type: 'error', error: { type: 'invalid_request_error', message: 'free model unavailable on this path' } });
    const unauthReport = await waitFor(() => hp.errors.find((e) => e.trace?.client_request_id === 'req-free-unauth'), `the free refusal report\n${logs}`);
    assert.equal(unauthReport.code, 'free_model_unauthorized');
    assert.equal(up.seen.filter((s) => s.path === '/api/v1/messages').at(-1), paidSent, 'nothing was sent upstream for the refused request');
    // hp's strip_tools directive lands in the Messages shape.
    const stripped = await post(inboundPort, '/v1/messages', REQ(null, { model: 'some/model-notools', tools: [{ name: 'f', input_schema: {} }], tool_choice: 'auto' }), { 'x-request-id': 'req-notools' });
    assert.equal(stripped.status, 200, stripped.body);
    const strippedSent = up.seen.filter((s) => s.path === '/api/v1/messages').at(-1);
    assert.equal('tools' in strippedSent.body, false, 'strip_tools removes the tools');
    assert.equal('tool_choice' in strippedSent.body, false);

    // 7. count_tokens: the enclave's own Anthropic key, only the count-bearing fields, the first-party id, nothing settled.
    const counted = await post(inboundPort, '/v1/messages/count_tokens', { model: 'anthropic/claude-sonnet-4.6', max_tokens: 10, stream: true, metadata: { user_id: 'u' }, messages: [{ role: 'user', content: 'hi' }], tools: [{ name: 't', input_schema: { type: 'object' } }] }, { 'x-request-id': 'req-count' });
    assert.equal(counted.status, 200, counted.body);
    assert.deepEqual(JSON.parse(counted.body), { input_tokens: 42 });
    const countSent = up.seen.find((s) => s.path === '/v1/messages/count_tokens');
    assert.deepEqual(Object.keys(countSent.body).sort(), ['messages', 'model', 'tools']);
    assert.equal(countSent.body.model, 'claude-sonnet-4-6-20260301', 'pinned to hp’s first-party id');
    assert.equal(countSent.headers['x-api-key'], 'anthropic-test-key');
    assert.equal(hp.authorizes.at(-1).intent, 'count_tokens', 'hp is told this authorize spends nothing');
    assert.equal(hp.authorizes.at(-1).endpoint, 'messages');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-count'), false, 'count_tokens never settles');

    // 8. A caller id outside the correlation-id shape never reaches hp: the
    // settle (and everything else) carries an enclave-minted id instead.
    // Node's parser accepts tabs and Latin-1 at any length below its 16 KB
    // header limit, so this 8 KB value arrives intact at the handler
    // (Oct 17-19 security reports: bgsparsiti finding 3, Rizki).
    up.setMode('stream');
    const hostileId = '\u00e9\tx'.repeat(2700);
    assert.ok(Buffer.byteLength(hostileId, 'latin1') > 8000);
    const before = hp.settles.length;
    const unbounded = await post(inboundPort, '/v1/messages', REQ(), { 'x-request-id': hostileId });
    assert.equal(unbounded.status, 200, unbounded.body);
    const boundedSettle = await waitFor(() => hp.settles.length > before && hp.settles.at(-1), `the bounded settle\n${logs}`);
    assert.match(boundedSettle.request_id, /^enc-\d{10,}-[a-f0-9]{8}$/, 'an enclave-minted id, not the caller value');
    assert.equal(boundedSettle.trace?.client_request_id, undefined, 'the trace drops it too');
    // Probe the SERIALIZED form: JSON.stringify escapes the tab to `\\t`, so a
    // literal-tab needle could never match and the check would pass vacuously
    // (CodeRabbit on #333). The needle itself is the sanity check for that:
    // it must be findable in a serialization that does carry the value.
    const needle = JSON.stringify('\u00e9\tx\u00e9').slice(1, -1);
    assert.ok(JSON.stringify([{ request_id: hostileId }]).includes(needle), 'the probe finds the value when present');
    assert.equal(JSON.stringify(hp.settles).includes(needle), false, 'no fragment of the caller value reached hp');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
