// pii_redaction on the dialect relay (/v1/messages, /v1/responses and its
// /responses alias), end to end through the real server: the upstream sees
// placeholders only, the client gets its own words back in its own dialect,
// every refusal speaks the dialect's error envelope with the PII code, a
// detector failure sends nothing anywhere, and detector calls on a request
// that never settles are reported (unbilled) rather than lost.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startPiiStack, haveOpenssl } from './piiServerHarness.mjs';

const PROMPT = 'Hi, I am Jane Roe, write to jane.roe@example.com';
const PLACEHOLDER = /⟦[A-Z]+_[0-9]+⟧/;
const SURFACE = /Jane Roe|jane\.roe@example\.com/;
const sse = (ev) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;
const pieces = (text) => text.match(/[\s\S]{1,3}/gu);

// --- Messages -------------------------------------------------------------
const M_MODEL = 'anthropic/claude-sonnet-4.6';
const mUserText = (body) => body.messages.at(-1).content;
const mReq = (extra) => ({ model: M_MODEL, max_tokens: 64, messages: [{ role: 'user', content: PROMPT }], ...extra });
const M_USAGE = { input_tokens: 12, output_tokens: 3, cost: 0.00021 };

function mEchoJson(body) {
  return { status: 200, contentType: 'application/json', body: JSON.stringify({
    id: 'gen-m1', type: 'message', role: 'assistant', model: M_MODEL, stop_reason: 'end_turn',
    content: [{ type: 'text', text: `You said: ${mUserText(body)}` }], usage: M_USAGE }) };
}
function mToolJson(body) {
  const [, who, email] = mUserText(body).match(/^Hi, I am (.+), write to (.+)$/);
  return { status: 200, contentType: 'application/json', body: JSON.stringify({
    id: 'gen-m2', type: 'message', role: 'assistant', model: M_MODEL, stop_reason: 'tool_use',
    content: [{ type: 'tool_use', id: 'toolu_1', name: 'send_email', input: { to: email, name: who } }], usage: M_USAGE }) };
}
/** The echo as Messages SSE, three characters a delta, 5 bytes a write; `cut` drops the closing events. */
function mEchoSse(body, { cut = false } = {}) {
  let out = sse({ type: 'message_start', message: { id: 'gen-m3', type: 'message', role: 'assistant', content: [], model: M_MODEL,
    stop_reason: null, usage: { input_tokens: 12, output_tokens: 1 } } });
  out += sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
  for (const p of pieces(`You said: ${mUserText(body)}`)) out += sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: p } });
  if (!cut) {
    out += sse({ type: 'content_block_stop', index: 0 });
    out += sse({ type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } });
    out += sse({ type: 'message_stop' });
  }
  return { status: 200, contentType: 'text/event-stream', body: out, chunkBytes: 5 };
}
const mStreamedText = (text) => text.split('\n').filter((l) => l.startsWith('data: {')).map((l) => JSON.parse(l.slice(6)))
  .filter((e) => e.type === 'content_block_delta' && e.delta?.type === 'text_delta').map((e) => e.delta.text).join('');

// --- Responses ------------------------------------------------------------
const R_MODEL = 'openai/gpt-5.5';
const rReq = (extra) => ({ model: R_MODEL, input: PROMPT, ...extra });
const R_USAGE = { input_tokens: 12, output_tokens: 3, total_tokens: 15, cost: 0.00021 };

function rEchoJson(body) {
  return { status: 200, contentType: 'application/json', body: JSON.stringify({
    id: 'gen-r1', object: 'response', model: R_MODEL, status: 'completed',
    output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: `You said: ${body.input}` }] }], usage: R_USAGE }) };
}
function rToolJson(body) {
  const [, who, email] = body.input.match(/^Hi, I am (.+), write to (.+)$/);
  return { status: 200, contentType: 'application/json', body: JSON.stringify({
    id: 'gen-r2', object: 'response', model: R_MODEL, status: 'completed',
    output: [{ type: 'function_call', call_id: 'call_1', name: 'send_email', arguments: JSON.stringify({ to: email, name: who }) }], usage: R_USAGE }) };
}
function rEchoSse(body) {
  const text = `You said: ${body.input}`;
  let out = sse({ type: 'response.created', sequence_number: 0, response: { id: 'gen-r3', object: 'response', model: R_MODEL, status: 'in_progress', usage: null } });
  for (const p of pieces(text)) out += sse({ type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, content_index: 0, delta: p });
  out += sse({ type: 'response.output_text.done', item_id: 'msg_1', output_index: 0, content_index: 0, text });
  out += sse({ type: 'response.completed', response: { id: 'gen-r3', object: 'response', model: R_MODEL, status: 'completed', usage: R_USAGE } });
  return { status: 200, contentType: 'text/event-stream', body: out, chunkBytes: 5 };
}
const rEvents = (text) => text.split('\n').filter((l) => l.startsWith('data: {')).map((l) => JSON.parse(l.slice(6)));
const rStreamedText = (text) => rEvents(text).filter((e) => e.type === 'response.output_text.delta').map((e) => e.delta).join('');

const ROUTES = [
  { path: '/v1/messages', req: mReq, echoJson: mEchoJson, echoSse: mEchoSse, toolJson: mToolJson, streamedText: mStreamedText,
    restoredText: (j) => j.content[0].text, toolArgs: (j) => j.content[0].input, sentText: mUserText },
  { path: '/v1/responses', req: rReq, echoJson: rEchoJson, echoSse: rEchoSse, toolJson: rToolJson, streamedText: rStreamedText,
    restoredText: (j) => j.output[0].content[0].text, toolArgs: (j) => JSON.parse(j.output[0].arguments), sentText: (b) => b.input },
  { path: '/responses', req: rReq, echoJson: rEchoJson, echoSse: rEchoSse, toolJson: rToolJson, streamedText: rStreamedText,
    restoredText: (j) => j.output[0].content[0].text, toolArgs: (j) => JSON.parse(j.output[0].arguments), sentText: (b) => b.input },
];

/** The dialect's own error envelope, carrying the PII code. */
function assertPiiError(path, r, status, code) {
  assert.equal(r.status, status, r.text);
  const j = JSON.parse(r.text);
  if (path === '/v1/messages') assert.equal(j.type, 'error', 'the Anthropic envelope');
  assert.equal(typeof j.error.message, 'string');
  assert.equal(j.error.code, code);
}

test('dialect relay redaction sandwich', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const s = await startPiiStack({ extraEnv: { PII_DETECTOR_TIMEOUT_MS: '1000' } });
  t.after(() => s.stop());
  const settleFor = (id) => s.waitFor(() => s.hp.settles.find((x) => x.request_id === id), `the settle for ${id}`);
  const newErrors = (from) => s.hp.errors.slice(from);
  const quiet = () => new Promise((ok) => setTimeout(ok, 300));

  for (const R of ROUTES) {
    await t.test(`${R.path} non-stream: placeholders upstream, the client gets its words back, the settle counts the call`, async () => {
      s.or.respond = R.echoJson;
      const r = await s.post(R.path, R.req({ pii_redaction: true }));
      assert.equal(r.status, 200, r.text);
      const sent = s.or.requests.at(-1);
      assert.doesNotMatch(sent.raw.toString('utf8'), SURFACE, 'no surface reaches the model upstream');
      assert.match(R.sentText(sent.body), PLACEHOLDER);
      assert.ok(!Object.hasOwn(sent.body, 'pii_redaction'), 'the flag never reaches OpenRouter');
      // The premise: the model answered with the placeholder, the client reads the original.
      assert.equal(R.restoredText(JSON.parse(r.text)), `You said: ${PROMPT}`);
      assert.doesNotMatch(r.text, PLACEHOLDER);
      assert.equal((await settleFor(r.requestId)).pii_redaction_calls, 1);
    });

    await t.test(`${R.path} stream: split events and split UTF-8 are restored`, async () => {
      s.or.respond = R.echoSse;
      const r = await s.post(R.path, R.req({ pii_redaction: true, stream: true }));
      assert.equal(r.status, 200, r.text);
      assert.doesNotMatch(s.or.requests.at(-1).raw.toString('utf8'), SURFACE);
      assert.equal(R.streamedText(r.text), `You said: ${PROMPT}`);
      assert.doesNotMatch(r.text, PLACEHOLDER, 'no placeholder reaches the client');
      assert.equal((await settleFor(r.requestId)).pii_redaction_calls, 1);
    });

    await t.test(`${R.path} tool arguments are restored as valid JSON`, async () => {
      s.or.respond = R.toolJson;
      const r = await s.post(R.path, R.req({ pii_redaction: true }));
      assert.equal(r.status, 200, r.text);
      assert.deepEqual(R.toolArgs(JSON.parse(r.text)), { to: 'jane.roe@example.com', name: 'Jane Roe' });
      await settleFor(r.requestId);
    });

    await t.test(`${R.path} flag absent and false: the same bytes go upstream, the detector is never asked`, async () => {
      s.or.respond = R.echoJson;
      const detects = s.detector.requests.length;
      const absent = await s.post(R.path, R.req());
      const absentRaw = s.or.requests.at(-1).raw;
      const off = await s.post(R.path, R.req({ pii_redaction: false }));
      const offRaw = s.or.requests.at(-1).raw;
      assert.equal(absent.status, 200, absent.text);
      assert.equal(off.status, 200, off.text);
      assert.equal(s.detector.requests.length, detects);
      assert.ok(absentRaw.equals(offRaw), 'absent and false forward the same bytes');
      assert.ok(absentRaw.toString('utf8').includes(PROMPT), 'the prompt goes out as written');
      const settle = await settleFor(absent.requestId);
      assert.ok(!Object.hasOwn(settle, 'pii_redaction_calls'), 'no redaction field on an unredacted settle');
    });

    await t.test(`${R.path} refusals before authorize: the dialect envelope, no authorize, no detector`, async () => {
      const auths = s.hp.authorizes.length;
      const detects = s.detector.requests.length;
      assertPiiError(R.path, await s.post(R.path, R.req({ pii_redaction: 'yes' })), 400, 'pii_redaction_invalid');
      assertPiiError(R.path, await s.post(R.path, R.req({ pii_redaction: true, model: 'private/some-model' })), 400, 'pii_redaction_unsupported_model');
      assert.equal(s.hp.authorizes.length, auths, 'no balance hold taken');
      assert.equal(s.detector.requests.length, detects);
    });

    await t.test(`${R.path} authorize carries the flag only when redaction is on`, async () => {
      s.or.respond = R.echoJson;
      await s.post(R.path, R.req({ pii_redaction: true }));
      assert.equal(s.hp.authorizes.at(-1).body.pii_redaction, true);
      await s.post(R.path, R.req());
      assert.ok(!Object.hasOwn(s.hp.authorizes.at(-1).body, 'pii_redaction'), 'flag absent: the authorize body is unchanged');
      await s.post(R.path, R.req({ pii_redaction: false }));
      assert.ok(!Object.hasOwn(s.hp.authorizes.at(-1).body, 'pii_redaction'), 'flag false: the authorize body is unchanged');
    });

    await t.test(`${R.path} hp refuses the redaction fee: 402 in the dialect envelope with the PII code, no detector, nothing upstream`, async () => {
      s.hp.authorizeStatus = 402;
      s.hp.authorizeRefusalBody = { error: { message: 'Insufficient credit for PII redaction', code: 'pii_redaction_insufficient_balance' } };
      const detects = s.detector.requests.length;
      const ors = s.or.requests.length;
      const r = await s.post(R.path, R.req({ pii_redaction: true }));
      s.hp.authorizeStatus = 200;
      s.hp.authorizeRefusalBody = null;
      assertPiiError(R.path, r, 402, 'pii_redaction_insufficient_balance');
      assert.equal(JSON.parse(r.text).error.message, 'Insufficient credit for PII redaction', "hp's message, restated");
      assert.equal(s.detector.requests.length, detects, 'the detector is never asked');
      assert.equal(s.or.requests.length, ors, 'nothing sent upstream');
    });

    await t.test(`${R.path} any other hp code is not relayed into the dialect envelope`, async () => {
      s.hp.authorizeStatus = 402;
      s.hp.authorizeRefusalBody = { error: { message: 'Insufficient credit', code: 'some_internal_code' } };
      const r = await s.post(R.path, R.req({ pii_redaction: true }));
      s.hp.authorizeStatus = 200;
      s.hp.authorizeRefusalBody = null;
      assert.equal(r.status, 402, r.text);
      assert.notEqual(JSON.parse(r.text).error.code, 'some_internal_code');
    });

    await t.test(`${R.path} detector failure: 503 in the dialect envelope, nothing upstream, no settle, a terminal report`, async () => {
      s.detector.mode = 'error';
      const ors = s.or.requests.length;
      const settles = s.hp.settles.length;
      const errs = s.hp.errors.length;
      const r = await s.post(R.path, R.req({ pii_redaction: true }));
      s.detector.mode = 'ok';
      assertPiiError(R.path, r, 503, 'pii_redaction_unavailable');
      const report = await s.waitFor(() => newErrors(errs).find((e) => e.code === 'pii_detector_failed'), 'the detector report');
      assert.equal(report.terminal, true, 'hp releases its hold');
      await quiet();
      assert.equal(s.or.requests.length, ors, 'nothing sent upstream');
      assert.equal(s.hp.settles.length, settles, 'nothing settled');
    });
  }

  await t.test('Responses with stored state is refused before authorize', async () => {
    const auths = s.hp.authorizes.length;
    assertPiiError('/v1/responses', await s.post('/v1/responses', rReq({ pii_redaction: true, previous_response_id: 'resp_1' })), 400, 'pii_redaction_unsupported_state');
    assertPiiError('/v1/responses', await s.post('/v1/responses', rReq({ pii_redaction: true, conversation: 'conv_1' })), 400, 'pii_redaction_unsupported_state');
    assert.equal(s.hp.authorizes.length, auths);
  });

  await t.test('an alias hp resolves onto a private model: 400, no detector, a terminal report', async () => {
    s.hp.authorizeExtra = () => ({ resolved_model: 'private/some-model' });
    const detects = s.detector.requests.length;
    const errs = s.hp.errors.length;
    const r = await s.post('/v1/messages', mReq({ pii_redaction: true }));
    s.hp.authorizeExtra = null;
    assertPiiError('/v1/messages', r, 400, 'pii_redaction_unsupported_model');
    const report = await s.waitFor(() => newErrors(errs).find((e) => e.code === 'model_rejected_private_path'), 'the rejection report');
    assert.equal(report.terminal, true);
    assert.equal(s.detector.requests.length, detects);
  });

  await t.test('an upstream refusal never settles; its detector calls ride the terminal report', async () => {
    s.or.respond = () => ({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: { message: 'Overloaded' } }) });
    const settles = s.hp.settles.length;
    const errs = s.hp.errors.length;
    const r = await s.post('/v1/messages', mReq({ pii_redaction: true }));
    assert.equal(r.status, 500);
    const report = await s.waitFor(() => newErrors(errs).find((e) => e.code === 'upstream_error_status'), 'the refusal report');
    assert.equal(report.terminal, true);
    assert.equal(report.pii_redaction_calls, 1);
    await quiet();
    assert.equal(s.hp.settles.length, settles);
  });

  await t.test('the client leaves during detection: no upstream call, no settle, the calls are reported', async () => {
    s.detector.mode = 'slow';
    s.or.respond = mEchoJson;
    const ors = s.or.requests.length;
    const settles = s.hp.settles.length;
    const errs = s.hp.errors.length;
    const r = await s.post('/v1/messages', mReq({ pii_redaction: true }), { abortAfterMs: 150 });
    assert.equal(r.aborted, true);
    const report = await s.waitFor(() => newErrors(errs).find((e) => e.code === 'client_abort' && e.pii_redaction_calls === 1), 'the abort report');
    s.detector.mode = 'ok';
    assert.equal(report.terminal, true);
    await quiet();
    assert.equal(s.or.requests.length, ors, 'no paid generation started');
    assert.equal(s.hp.settles.length, settles);
  });

  await t.test('a stream cut before message_stop: restored text first, then the in-band error, then a settle', async () => {
    s.or.respond = (body) => mEchoSse(body, { cut: true });
    const r = await s.post('/v1/messages', mReq({ pii_redaction: true, stream: true }));
    assert.equal(r.status, 200);
    assert.equal(mStreamedText(r.text), `You said: ${PROMPT}`, 'everything the upstream sent is delivered, restored');
    const events = r.text.split('\n').filter((l) => l.startsWith('data: {')).map((l) => JSON.parse(l.slice(6)));
    const lastText = events.findLastIndex((e) => e.type === 'content_block_delta');
    const errorAt = events.findIndex((e) => e.type === 'error');
    assert.ok(errorAt > lastText, 'the error frame comes after the flushed tail');
    assert.equal((await settleFor(r.requestId)).pii_redaction_calls, 1);
  });

  await t.test('/health counts detector calls that never settled', async () => {
    const h = await new Promise((resolve, reject) => {
      import('node:https').then(({ default: https }) => https.get({ host: '127.0.0.1', port: s.inboundPort, path: '/health', rejectUnauthorized: false }, (res) => {
        let b = '';
        res.on('data', (c) => { b += c; });
        res.on('end', () => resolve(JSON.parse(b)));
      }).on('error', reject));
    });
    // Two so far: the upstream refusal and the client that left.
    assert.equal(h.pii_redaction.unbilled_calls, 2, JSON.stringify(h.pii_redaction));
  });

  await t.test('count_tokens: true is refused before anything leaves, false is counted as without the flag', async () => {
    const auths = s.hp.authorizes.length;
    const detects = s.detector.requests.length;
    const count = (extra) => s.post('/v1/messages/count_tokens', { model: M_MODEL, messages: [{ role: 'user', content: PROMPT }], ...extra });
    assertPiiError('/v1/messages', await count({ pii_redaction: true }), 400, 'pii_redaction_unsupported_endpoint');
    assertPiiError('/v1/messages', await count({ pii_redaction: 1 }), 400, 'pii_redaction_invalid');
    assert.equal(s.hp.authorizes.length, auths);
    // This stack has no Anthropic upstream: past the flag, both answer the deployment's own 503.
    const off = await count({ pii_redaction: false });
    const absent = await count();
    assert.equal(off.status, absent.status);
    assert.equal(off.text, absent.text);
    assert.equal(s.detector.requests.length, detects);
  });
});
