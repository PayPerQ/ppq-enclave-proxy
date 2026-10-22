import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pseudonymize as pseudonymizeWith } from '../src/pii/core.mjs';
import { extractTexts, applyTexts, restoreJson, createEventRestorer } from '../src/pii/dialects/responses.mjs';

// Fixtures below are written in the `square` grammar; the default grammar is
// covered on its own in pii-core.test.mjs.
const pseudonymize = (texts, spans, opts = {}) => pseudonymizeWith(texts, spans, { grammar: 'square', ...opts });

// Fictional PII only.
const PII = { 'Jane Roe': 'PERSON', 'jane.roe@example.com': 'EMAIL', 'Acme Corp': 'ORG' };
function fakeDetect(texts) {
  return texts.map((t) => {
    const spans = [];
    for (const [s, cls] of Object.entries(PII)) {
      for (let i = t.indexOf(s); i >= 0; i = t.indexOf(s, i + 1)) spans.push({ start: i, end: i + s.length, cls });
    }
    return spans;
  });
}
function redact(body, policy) {
  const refs = extractTexts(body, policy);
  const texts = refs.map((r) => r.text);
  const p = pseudonymize(texts, fakeDetect(texts));
  return { body: applyTexts(body, refs, p.texts), mapping: p.mapping };
}

const REQUEST = {
  model: 'some/model',
  instructions: 'Operator is Acme Corp.',
  tools: [{ type: 'function', name: 'send_mail', parameters: { type: 'object' } }],
  input: [
    { role: 'developer', content: 'Company: Acme Corp' },
    { role: 'user', content: [
      { type: 'input_text', text: 'I am Jane Roe (jane.roe@example.com) of Acme Corp.' },
      { type: 'input_image', image_url: 'data:image/png;base64,Jane Roe' },
    ] },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Hi Jane Roe' }] },
    { type: 'reasoning', id: 'rs_1', summary: [{ type: 'summary_text', text: 'User Jane Roe wants mail' }] },
    { type: 'function_call', call_id: 'c1', name: 'send_mail', arguments: '{"to":"jane.roe@example.com"}' },
    { type: 'function_call_output', call_id: 'c1', output: 'ok, mailed Jane Roe' },
    { role: 'user', content: 'thanks' },
  ],
};

test('string input is redacted', () => {
  const { body } = redact({ model: 'm', input: 'Email jane.roe@example.com for Jane Roe' });
  assert.equal(body.input, 'Email [EMAIL_1] for [PERSON_1]');
});

test('PII-10/24: user + assistant items, function_call args/output and reasoning summaries are redacted', () => {
  const { body } = redact(REQUEST);
  const [dev, user, asst, rs, fc, fco] = body.input;
  assert.equal(dev.content, 'Company: Acme Corp', 'developer message untouched');
  assert.equal(body.instructions, REQUEST.instructions, 'instructions untouched');
  assert.equal(user.content[0].text, 'I am [PERSON_1] ([EMAIL_1]) of [ORG_1].');
  assert.deepEqual(user.content[1], REQUEST.input[1].content[1], 'image untouched');
  assert.equal(asst.content[0].text, 'Hi [PERSON_1]');
  assert.equal(rs.summary[0].text, 'User [PERSON_1] wants mail');
  assert.deepEqual(JSON.parse(fc.arguments), { to: '[EMAIL_1]' });
  assert.equal(fco.output, 'ok, mailed [PERSON_1]');
  assert.deepEqual(body.tools, REQUEST.tools);
  assert.equal(REQUEST.input[1].content[0].text, 'I am Jane Roe (jane.roe@example.com) of Acme Corp.', 'input not mutated');
});

test('policy.includeSystem opts selected system/developer text in', () => {
  const { body } = redact(REQUEST, { includeSystem: (t) => t.startsWith('Company:') });
  assert.equal(body.input[0].content, 'Company: [ORG_1]');
});

function runStream(mapping, events) {
  const r = createEventRestorer(mapping);
  return [...events.flatMap((e) => r.push(e)), ...r.flush()];
}
const deltas = (out, type) => out.filter((e) => e.type === type).map((e) => e.delta).join('');

test('PII-19: output_text deltas split mid-placeholder are restored; .done text restored', () => {
  const { mapping } = redact(REQUEST);
  const d = (delta, n) => ({ type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, content_index: 0, delta, sequence_number: n });
  const out = runStream(mapping, [
    d('Dear [PERS', 1), d('ON_1] at [ORG', 2), d('_1].', 3),
    { type: 'response.output_text.done', item_id: 'msg_1', output_index: 0, content_index: 0, text: 'Dear [PERSON_1] at [ORG_1].', sequence_number: 4 },
  ]);
  assert.equal(deltas(out, 'response.output_text.delta'), 'Dear Jane Roe at Acme Corp.');
  assert.equal(out.find((e) => e.type === 'response.output_text.done').text, 'Dear Jane Roe at Acme Corp.');
});

test('PII-22: a held tail is emitted as a synthetic delta right before its .done event', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [
    { type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, content_index: 0, delta: 'end [PERS', sequence_number: 1 },
    { type: 'response.output_text.done', item_id: 'msg_1', output_index: 0, content_index: 0, text: 'end [PERS', sequence_number: 2 },
  ]);
  assert.deepEqual(out.map((e) => e.type), ['response.output_text.delta', 'response.output_text.delta', 'response.output_text.done']);
  assert.deepEqual(out[1], { type: 'response.output_text.delta', item_id: 'msg_1', output_index: 0, content_index: 0, delta: '[PERS', sequence_number: 2 });
  assert.equal(deltas(out, 'response.output_text.delta'), 'end [PERS');
});

test('PII-22: stream cut before .done — flush() emits the tail', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [{ type: 'response.output_text.delta', item_id: 'm', output_index: 0, content_index: 0, delta: 'x [EMAIL_', sequence_number: 7 }]);
  assert.equal(deltas(out, 'response.output_text.delta'), 'x [EMAIL_');
  assert.equal(out.length, 2);
});

test('PII-27: function_call_arguments deltas and .done are restored as valid JSON', () => {
  const m = { byPlaceholder: new Map([['[PERSON_1]', 'Jane "JR" Roe']]), grammar: { open: '[', close: ']' } };
  const a = (delta) => ({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 1, delta });
  const out = runStream(m, [
    a('{"who":"[PER'), a('SON_1]"}'),
    { type: 'response.function_call_arguments.done', item_id: 'fc_1', output_index: 1, arguments: '{"who":"[PERSON_1]"}' },
    { type: 'response.output_item.done', output_index: 1, item: { type: 'function_call', id: 'fc_1', call_id: 'c', name: 'f', arguments: '{"who":"[PERSON_1]"}' } },
  ]);
  assert.deepEqual(JSON.parse(deltas(out, 'response.function_call_arguments.delta')), { who: 'Jane "JR" Roe' });
  assert.deepEqual(JSON.parse(out.find((e) => e.type === 'response.function_call_arguments.done').arguments), { who: 'Jane "JR" Roe' });
  assert.deepEqual(JSON.parse(out.find((e) => e.type === 'response.output_item.done').item.arguments), { who: 'Jane "JR" Roe' });
});

test('separate content parts / items keep separate buffers', () => {
  const { mapping } = redact(REQUEST);
  const d = (item, delta) => ({ type: 'response.output_text.delta', item_id: item, output_index: 0, content_index: 0, delta });
  const out = runStream(mapping, [d('a', 'A [PERS'), d('b', 'B [ORG'), d('a', 'ON_1]'), d('b', '_1]')]);
  assert.equal(out.filter((e) => e.item_id === 'a').map((e) => e.delta).join(''), 'A Jane Roe');
  assert.equal(out.filter((e) => e.item_id === 'b').map((e) => e.delta).join(''), 'B Acme Corp');
});

test('content_part.done, reasoning summary and response.completed are restored', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [
    { type: 'response.reasoning_summary_text.delta', item_id: 'rs', output_index: 0, summary_index: 0, delta: 'about [PERSON_1]' },
    { type: 'response.content_part.done', item_id: 'm', output_index: 1, content_index: 0, part: { type: 'output_text', text: 'Hi [PERSON_1]', annotations: [] } },
    { type: 'response.completed', response: { id: 'resp_1', status: 'completed', usage: { input_tokens: 1 }, output: [
      { type: 'reasoning', id: 'rs', summary: [{ type: 'summary_text', text: 'about [PERSON_1]' }] },
      { type: 'message', id: 'm', role: 'assistant', content: [{ type: 'output_text', text: 'Hi [PERSON_1], [EMAIL_1]' }] },
    ] } },
  ]);
  assert.equal(out[0].delta, 'about Jane Roe');
  assert.equal(out[1].part.text, 'Hi Jane Roe');
  assert.equal(out[2].response.output[0].summary[0].text, 'about Jane Roe');
  assert.equal(out[2].response.output[1].content[0].text, 'Hi Jane Roe, jane.roe@example.com');
  assert.deepEqual(out[2].response.usage, { input_tokens: 1 });
});

test('unrelated events pass through unchanged', () => {
  const { mapping } = redact(REQUEST);
  const e = { type: 'response.created', sequence_number: 0, response: { id: 'r', output: [] } };
  assert.deepEqual(runStream(mapping, [e]), [e]);
});

test('PII-20: non-stream Responses body — message text, refusal and function_call args restored', () => {
  const { mapping } = redact(REQUEST);
  const body = {
    id: 'resp_1', object: 'response', status: 'completed',
    output: [
      { type: 'message', role: 'assistant', content: [
        { type: 'output_text', text: '[PERSON_1] works at [ORG_1]; [PERSON_7] unknown' },
        { type: 'refusal', refusal: 'cannot mail [EMAIL_1]' },
      ] },
      { type: 'function_call', call_id: 'c', name: 'f', arguments: '{"to":"[EMAIL_1]"}' },
    ],
  };
  const out = restoreJson(body, mapping);
  assert.equal(out.output[0].content[0].text, 'Jane Roe works at Acme Corp; [PERSON_7] unknown');
  assert.equal(out.output[0].content[1].refusal, 'cannot mail jane.roe@example.com');
  assert.deepEqual(JSON.parse(out.output[1].arguments), { to: 'jane.roe@example.com' });
  assert.equal(body.output[0].content[0].text.startsWith('[PERSON_1]'), true, 'input not mutated');
});

// Codex review 2026-10-21: function_call arguments are redacted on their
// decoded string leaves, not on the escaped JSON text.
test('function_call arguments: a quoted name restores without extra escapes', () => {
  const QUOTED = 'Jane "JR" Roe';
  const detect = (texts) => texts.map((t) => {
    const i = t.indexOf(QUOTED);
    return i < 0 ? [] : [{ start: i, end: i + QUOTED.length, cls: 'PERSON' }];
  });
  const req = { model: 'm', input: [
    { type: 'function_call', call_id: 'c1', name: 'f', arguments: JSON.stringify({ who: QUOTED, deep: { list: [QUOTED] } }) },
  ] };
  const refs = extractTexts(req);
  assert.ok(!refs.some((r) => r.text.includes('\\"')), 'never the escaped JSON text');
  const texts = refs.map((r) => r.text);
  const p = pseudonymize(texts, detect(texts));
  const body = applyTexts(req, refs, p.texts);
  assert.deepEqual(JSON.parse(body.input[0].arguments), { who: '[PERSON_1]', deep: { list: ['[PERSON_1]'] } });
  const out = restoreJson({ output: [{ type: 'function_call', call_id: 'c', name: 'f', arguments: '{"who":"[PERSON_1]"}' }] }, p.mapping);
  assert.deepEqual(JSON.parse(out.output[0].arguments), { who: QUOTED });
});
