import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pseudonymize } from '../src/pii/core.mjs';
import { extractTexts, applyTexts, restoreJson, createEventRestorer } from '../src/pii/dialects/messages.mjs';

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
function redact(body) {
  const refs = extractTexts(body);
  const texts = refs.map((r) => r.text);
  const p = pseudonymize(texts, fakeDetect(texts));
  return { body: applyTexts(body, refs, p.texts), mapping: p.mapping };
}

const REQUEST = {
  model: 'some/model',
  max_tokens: 100,
  system: 'You work for Acme Corp. Customer: Jane Roe.',
  tools: [{ name: 'send_mail', input_schema: { type: 'object' } }],
  messages: [
    { role: 'user', content: 'I am Jane Roe of Acme Corp.' },
    { role: 'assistant', content: [
      { type: 'thinking', thinking: 'User is Jane Roe', signature: 'sig' },
      { type: 'text', text: 'Mailing Jane Roe.' },
      { type: 'tool_use', id: 'tu1', name: 'send_mail', input: { to: 'jane.roe@example.com', cc: ['Jane Roe'], n: 3 } },
    ] },
    { role: 'user', content: [
      { type: 'tool_result', tool_use_id: 'tu1', content: 'sent to jane.roe@example.com' },
      { type: 'tool_result', tool_use_id: 'tu2', content: [{ type: 'text', text: 'Jane Roe ok' }, { type: 'image', source: { type: 'base64', data: 'Jane Roe' } }] },
      { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'Jane Roe' } },
      { type: 'text', text: 'thanks' },
    ] },
  ],
};

test('PII-24: user/assistant text, tool_use input leaves and tool_result text are redacted', () => {
  const { body } = redact(REQUEST);
  const [u, a, r] = body.messages;
  assert.equal(u.content, 'I am [PERSON_1] of [ORG_1].');
  assert.equal(a.content[1].text, 'Mailing [PERSON_1].');
  assert.deepEqual(a.content[2].input, { to: '[EMAIL_1]', cc: ['[PERSON_1]'], n: 3 });
  assert.equal(r.content[0].content, 'sent to [EMAIL_1]');
  assert.equal(r.content[1].content[0].text, '[PERSON_1] ok');
  assert.deepEqual(r.content[1].content[1], REQUEST.messages[2].content[1].content[1], 'image in tool_result untouched');
  assert.deepEqual(r.content[2], REQUEST.messages[2].content[2], 'image untouched');
});

test('system prompt and signed thinking blocks are untouched; input not mutated', () => {
  const before = JSON.stringify(REQUEST);
  const { body } = redact(REQUEST);
  assert.equal(body.system, REQUEST.system);
  assert.deepEqual(body.messages[1].content[0], REQUEST.messages[1].content[0]);
  assert.deepEqual(body.tools, REQUEST.tools);
  assert.equal(JSON.stringify(REQUEST), before);
});

test('system as a list of blocks is also untouched', () => {
  const req = { system: [{ type: 'text', text: 'Jane Roe' }], messages: [{ role: 'user', content: 'hi' }] };
  assert.deepEqual(extractTexts(req).map((r) => r.path), [['messages', 0, 'content']]);
});

function runStream(mapping, events) {
  const r = createEventRestorer(mapping);
  return [...events.flatMap((e) => r.push(e)), ...r.flush()];
}
const cbd = (index, delta) => ({ type: 'content_block_delta', index, delta });
const texts = (out, index) => out.filter((e) => e.type === 'content_block_delta' && e.index === index)
  .map((e) => e.delta.text ?? e.delta.partial_json ?? '').join('');

test('PII-19: text_delta split mid-placeholder is restored', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [
    { type: 'message_start', message: { id: 'msg', role: 'assistant', content: [], usage: { input_tokens: 1 } } },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
    cbd(0, { type: 'text_delta', text: 'Hi [PER' }),
    { type: 'ping' },
    cbd(0, { type: 'text_delta', text: 'SON_1] of [ORG_1]' }),
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 } },
    { type: 'message_stop' },
  ]);
  assert.equal(texts(out, 0), 'Hi Jane Roe of Acme Corp');
  assert.deepEqual(out.map((e) => e.type), ['message_start', 'content_block_start', 'content_block_delta', 'ping', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop']);
});

test('PII-22: a held tail becomes a synthetic content_block_delta just before content_block_stop', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [cbd(0, { type: 'text_delta', text: 'bye [PERS' }), { type: 'content_block_stop', index: 0 }]);
  assert.deepEqual(out, [
    cbd(0, { type: 'text_delta', text: 'bye ' }),
    cbd(0, { type: 'text_delta', text: '[PERS' }),
    { type: 'content_block_stop', index: 0 },
  ]);
});

test('PII-22: stream cut before content_block_stop — flush() emits the tail', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [cbd(2, { type: 'text_delta', text: 'x [EMAIL' })]);
  assert.deepEqual(out.at(-1), cbd(2, { type: 'text_delta', text: '[EMAIL' }));
  assert.equal(texts(out, 2), 'x [EMAIL');
});

test('PII-27: input_json_delta is restored as valid JSON; blocks keep separate buffers', () => {
  const m = { byPlaceholder: new Map([['[PERSON_1]', 'Jane "JR" Roe']]), grammar: { open: '[', close: ']' } };
  const out = runStream(m, [
    { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 'tu', name: 'f', input: {} } },
    cbd(0, { type: 'text_delta', text: 'A [PERS' }),
    cbd(1, { type: 'input_json_delta', partial_json: '{"who":"[PER' }),
    cbd(0, { type: 'text_delta', text: 'ON_1]' }),
    cbd(1, { type: 'input_json_delta', partial_json: 'SON_1]"}' }),
    { type: 'content_block_stop', index: 0 },
    { type: 'content_block_stop', index: 1 },
  ]);
  assert.equal(texts(out, 0), 'A Jane "JR" Roe');
  assert.deepEqual(JSON.parse(texts(out, 1)), { who: 'Jane "JR" Roe' });
});

test('thinking_delta and signature_delta pass through untouched', () => {
  const { mapping } = redact(REQUEST);
  const evs = [cbd(0, { type: 'thinking_delta', thinking: 'about [PERSON_1]' }), cbd(0, { type: 'signature_delta', signature: 'abc' })];
  assert.deepEqual(runStream(mapping, evs), evs);
});

test('events are not mutated', () => {
  const { mapping } = redact(REQUEST);
  const e = cbd(0, { type: 'text_delta', text: '[PERSON_1]' });
  const before = JSON.stringify(e);
  createEventRestorer(mapping).push(e);
  assert.equal(JSON.stringify(e), before);
});

test('PII-20: non-stream body — text blocks and tool_use input restored, thinking untouched', () => {
  const { mapping } = redact(REQUEST);
  const body = {
    id: 'msg', type: 'message', role: 'assistant', stop_reason: 'tool_use',
    content: [
      { type: 'thinking', thinking: 'for [PERSON_1]', signature: 's' },
      { type: 'text', text: '[PERSON_1] at [ORG_1]; [ORG_4] unknown' },
      { type: 'tool_use', id: 'tu', name: 'f', input: { to: '[EMAIL_1]', list: ['[PERSON_1]', 2] } },
    ],
    usage: { input_tokens: 1 },
  };
  const out = restoreJson(body, mapping);
  assert.equal(out.content[0].thinking, 'for [PERSON_1]');
  assert.equal(out.content[1].text, 'Jane Roe at Acme Corp; [ORG_4] unknown');
  assert.deepEqual(out.content[2].input, { to: 'jane.roe@example.com', list: ['Jane Roe', 2] });
  assert.equal(body.content[1].text.startsWith('[PERSON_1]'), true, 'input not mutated');
});
