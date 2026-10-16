// The /v1/chat/completions redaction sandwich, end to end through the real
// server: the model upstream sees placeholders only, the client gets its own
// words back (streamed and not, tool-call arguments included), a detector
// failure sends nothing anywhere, and the settle counts the detector calls.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startPiiStack, haveOpenssl } from './piiServerHarness.mjs';

const MODEL = 'openai/gpt-4.1-mini';
const PROMPT = 'Hi, I am Jane Roe, write to jane.roe@example.com';
const PLACEHOLDER = /⟦[A-Z]+_[0-9]+⟧/;
const SURFACE = /Jane Roe|jane\.roe@example\.com/;

const lastUserText = (body) => body.messages.at(-1).content;
const usage = { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 };

/** Echo the (redacted) prompt back, as the model would quote it. */
function echoJson(body) {
  return {
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ id: 'gen-1', object: 'chat.completion', model: MODEL,
      choices: [{ index: 0, message: { role: 'assistant', content: `You said: ${lastUserText(body)}` }, finish_reason: 'stop' }], usage }),
  };
}

/** A tool call whose arguments carry the placeholders the model was given. */
function toolCallJson(body) {
  const [, who, email] = lastUserText(body).match(/^Hi, I am (.+), write to (.+)$/);
  return {
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ id: 'gen-2', object: 'chat.completion', model: MODEL,
      choices: [{ index: 0, finish_reason: 'tool_calls', message: { role: 'assistant', content: null,
        tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'send_email', arguments: JSON.stringify({ to: email, name: who }) } }] } }],
      usage }),
  };
}

/** The echo as SSE, three characters a delta, written 5 bytes at a time. */
function echoSse(body) {
  const text = `You said: ${lastUserText(body)}`;
  const chunk = (delta, extra = {}) => `data: ${JSON.stringify({ id: 'gen-3', object: 'chat.completion.chunk', model: MODEL,
    choices: [{ index: 0, delta, finish_reason: null }], ...extra })}\n\n`;
  let sse = chunk({ role: 'assistant', content: '' });
  for (const piece of [...text].join('').match(/[\s\S]{1,3}/gu)) sse += chunk({ content: piece });
  sse += `data: ${JSON.stringify({ id: 'gen-3', object: 'chat.completion.chunk', model: MODEL, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })}\n\n`;
  sse += `data: ${JSON.stringify({ id: 'gen-3', object: 'chat.completion.chunk', model: MODEL, choices: [], usage })}\n\n`;
  sse += 'data: [DONE]\n\n';
  return { status: 200, contentType: 'text/event-stream', body: sse, chunkBytes: 5 };
}

const streamedText = (sse) => sse.split('\n')
  .filter((l) => l.startsWith('data: {'))
  .map((l) => JSON.parse(l.slice(6)).choices?.[0]?.delta?.content ?? '')
  .join('');

const chatReq = (extra) => ({ model: MODEL, stream: false, messages: [{ role: 'user', content: PROMPT }], ...extra });

test('chat completions redaction sandwich', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const s = await startPiiStack({ extraEnv: { PII_DETECTOR_TIMEOUT_MS: '300' } });
  t.after(() => s.stop());
  const settleFor = (id) => s.waitFor(() => s.hp.settles.find((x) => x.request_id === id), `the settle for ${id}`);

  await t.test('non-stream: placeholders upstream, the client gets its words back, the settle counts one call', async () => {
    s.or.respond = echoJson;
    const r = await s.chat(chatReq({ pii_redaction: true }));
    assert.equal(r.status, 200, r.text);
    const sent = s.or.requests.at(-1);
    assert.doesNotMatch(sent.raw.toString('utf8'), SURFACE, 'no surface reaches the model upstream');
    assert.match(lastUserText(sent.body), PLACEHOLDER);
    assert.equal(JSON.parse(r.text).choices[0].message.content, `You said: ${PROMPT}`);
    assert.equal((await settleFor(r.requestId)).pii_redaction_calls, 1);
  });

  await t.test('stream: split events and split UTF-8 are restored', async () => {
    s.or.respond = echoSse;
    const r = await s.chat(chatReq({ pii_redaction: true, stream: true }));
    assert.equal(r.status, 200, r.text);
    assert.doesNotMatch(s.or.requests.at(-1).raw.toString('utf8'), SURFACE);
    assert.equal(streamedText(r.text), `You said: ${PROMPT}`);
    assert.doesNotMatch(r.text, PLACEHOLDER, 'no placeholder reaches the client');
    assert.match(r.text, /data: \[DONE\]/);
    assert.equal((await settleFor(r.requestId)).pii_redaction_calls, 1);
  });

  await t.test('tool-call arguments are restored as valid JSON', async () => {
    s.or.respond = toolCallJson;
    const r = await s.chat(chatReq({ pii_redaction: true }));
    assert.equal(r.status, 200, r.text);
    const args = JSON.parse(JSON.parse(r.text).choices[0].message.tool_calls[0].function.arguments);
    assert.deepEqual(args, { to: 'jane.roe@example.com', name: 'Jane Roe' });
    await settleFor(r.requestId);
  });

  await t.test('the resent conversation is redacted again, tool-call arguments included', async () => {
    s.or.respond = echoJson;
    const r = await s.chat({ model: MODEL, pii_redaction: true, messages: [
      { role: 'user', content: 'Email Jane Roe.' },
      { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'send_email', arguments: '{"to":"jane.roe@example.com"}' } }] },
      { role: 'tool', tool_call_id: 'call_1', content: 'sent to jane.roe@example.com' },
      { role: 'user', content: PROMPT },
    ] });
    assert.equal(r.status, 200, r.text);
    assert.doesNotMatch(s.or.requests.at(-1).raw.toString('utf8'), SURFACE);
    await settleFor(r.requestId);
  });

  for (const mode of ['error', 'unknown_label', 'hang']) {
    await t.test(`detector ${mode}: 503 pii_redaction_unavailable, zero upstream calls, zero settles`, async () => {
      s.detector.mode = mode;
      const ors = s.or.requests.length;
      const settles = s.hp.settles.length;
      const r = await s.chat(chatReq({ pii_redaction: true }));
      s.detector.mode = 'ok';
      assert.equal(r.status, 503);
      assert.equal(JSON.parse(r.text).error.code, 'pii_redaction_unavailable');
      await new Promise((ok) => setTimeout(ok, 300));
      assert.equal(s.or.requests.length, ors, 'nothing sent upstream');
      assert.equal(s.hp.settles.length, settles, 'nothing settled');
      assert.ok(!s.hp.settles.some((x) => x.request_id === r.requestId));
    });
  }

  await t.test('authorize carries the flag only when redaction is on', async () => {
    s.or.respond = echoSse;
    await s.chat(chatReq({ stream: true, pii_redaction: true }));
    assert.equal(s.hp.authorizes.at(-1).body.pii_redaction, true);
    await s.chat(chatReq({ stream: true }));
    assert.ok(!Object.hasOwn(s.hp.authorizes.at(-1).body, 'pii_redaction'));
    await s.chat(chatReq({ stream: true, pii_redaction: false }));
    assert.ok(!Object.hasOwn(s.hp.authorizes.at(-1).body, 'pii_redaction'));
  });

  await t.test("hp refuses the redaction fee: its 402 body reaches the client verbatim, no detector, nothing upstream", async () => {
    s.hp.authorizeStatus = 402;
    s.hp.authorizeRefusalBody = { error: { message: 'Insufficient credit for PII redaction', code: 'pii_redaction_insufficient_balance' } };
    const detects = s.detector.requests.length;
    const ors = s.or.requests.length;
    const r = await s.chat(chatReq({ pii_redaction: true }));
    s.hp.authorizeStatus = 200;
    s.hp.authorizeRefusalBody = null;
    assert.equal(r.status, 402, r.text);
    assert.deepEqual(JSON.parse(r.text), { error: { message: 'Insufficient credit for PII redaction', code: 'pii_redaction_insufficient_balance' } });
    assert.equal(s.detector.requests.length, detects);
    assert.equal(s.or.requests.length, ors);
  });

  await t.test('flag absent: the upstream body and the client bytes are what they are without the feature', async () => {
    s.or.respond = echoSse;
    const detects = s.detector.requests.length;
    const absent = await s.chat(chatReq({ stream: true }));
    const absentRaw = s.or.requests.at(-1).raw;
    const off = await s.chat(chatReq({ stream: true, pii_redaction: false }));
    const offRaw = s.or.requests.at(-1).raw;
    assert.equal(s.detector.requests.length, detects, 'the detector is never asked');
    assert.ok(absentRaw.equals(offRaw), 'absent and false forward the same bytes');
    assert.ok(absentRaw.toString('utf8').includes(PROMPT), 'the prompt goes out as written');
    // The only enclave-written bytes are the signed routing receipt (ECDSA:
    // a fresh signature each time); everything after it is the upstream's.
    const upstreamSse = echoSse(JSON.parse(absentRaw.toString('utf8'))).body;
    const afterReceipt = (text) => text.replace(/^(: ppq-routing-receipt[^\n]*\n\n)+/, '');
    assert.equal(afterReceipt(absent.text), upstreamSse, 'absent: the stream is passed through untouched');
    assert.equal(afterReceipt(off.text), upstreamSse, 'false: the stream is passed through untouched');
    assert.equal(streamedText(absent.text), `You said: ${PROMPT}`);
    const settle = await settleFor(absent.requestId);
    assert.ok(!Object.hasOwn(settle, 'pii_redaction_calls'), 'no redaction field on an unredacted settle');
  });
});
