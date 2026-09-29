import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pseudonymize as pseudonymizeWith } from '../src/pii/core.mjs';
import { extractTexts, applyTexts, restoreJson, createEventRestorer } from '../src/pii/dialects/chat.mjs';

// Fixtures below are written in the `square` grammar; the default grammar is
// covered on its own in pii-core.test.mjs.
const pseudonymize = (texts, spans, opts = {}) => pseudonymizeWith(texts, spans, { grammar: 'square', ...opts });

// Fictional PII only. A fake "detector": every occurrence of each known surface.
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
const noSurface = (s) => !Object.keys(PII).some((x) => s.includes(x));

const REQUEST = {
  model: 'some/model',
  stream: true,
  plugins: [{ id: 'web' }],
  tools: [{ type: 'function', function: { name: 'send_mail', parameters: { type: 'object' } } }],
  messages: [
    { role: 'system', content: 'You are helpful. Operator: Acme Corp.' },
    { role: 'system', content: 'Document Content (cv.pdf): Jane Roe, Acme Corp' },
    { role: 'user', content: [
      { type: 'text', text: 'I am Jane Roe from Acme Corp.' },
      { type: 'image_url', image_url: { url: 'data:image/png;base64,Jane Roe' } },
    ] },
    { role: 'assistant', content: 'Hello Jane Roe.', reasoning: 'User is Jane Roe.',
      tool_calls: [{ id: 'c1', type: 'function', function: { name: 'send_mail', arguments: '{"to":"jane.roe@example.com"}' } }] },
    { role: 'tool', tool_call_id: 'c1', content: 'sent to jane.roe@example.com' },
    { role: 'user', content: 'Thanks' },
    { role: 'user', content: '' },
  ],
};

test('PII-10: user, assistant (incl. tool-call args, reasoning) and tool text are redacted; system is not', () => {
  const { body } = redact(REQUEST);
  const [sys, doc, user, asst, tool] = body.messages;
  assert.equal(sys.content, REQUEST.messages[0].content, 'system prompt sent as-is');
  assert.equal(doc.content, REQUEST.messages[1].content, 'documents not opted in: sent as-is');
  assert.equal(user.content[0].text, 'I am [PERSON_1] from [ORG_1].');
  assert.equal(asst.content, 'Hello [PERSON_1].');
  assert.equal(asst.reasoning, 'User is [PERSON_1].');
  assert.deepEqual(JSON.parse(asst.tool_calls[0].function.arguments), { to: '[EMAIL_1]' });
  assert.equal(tool.content, 'sent to [EMAIL_1]');
  assert.ok(noSurface(JSON.stringify(body.messages.slice(2).map((m) => ({ ...m, content: Array.isArray(m.content) ? m.content.filter((p) => p.type === 'text') : m.content })))));
});

test('PII-14: image parts are untouched', () => {
  const { body } = redact(REQUEST);
  assert.deepEqual(body.messages[2].content[1], REQUEST.messages[2].content[1]);
});

test('policy.includeSystem opts selected system text in (web documents)', () => {
  const { body } = redact(REQUEST, { includeSystem: (t) => t.startsWith('Document Content (') });
  assert.equal(body.messages[1].content, 'Document Content (cv.pdf): [PERSON_1], [ORG_1]');
  assert.equal(body.messages[0].content, REQUEST.messages[0].content);
});

test('non-message fields (model, tools, plugins, stream) are preserved and the input is not mutated', () => {
  const before = JSON.stringify(REQUEST);
  const { body } = redact(REQUEST);
  assert.equal(JSON.stringify(REQUEST), before);
  for (const k of ['model', 'stream', 'plugins', 'tools']) assert.deepEqual(body[k], REQUEST[k]);
  assert.deepEqual(Object.keys(body), Object.keys(REQUEST));
});

test('empty strings are not extracted (detector not called for them)', () => {
  const refs = extractTexts(REQUEST);
  assert.ok(refs.every((r) => r.text.trim() !== ''));
  assert.deepEqual(extractTexts({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'x' } }] }] }), []);
  assert.deepEqual(extractTexts({}), []);
});

const chunk = (delta, extra = {}) => ({ id: 'gen-1', object: 'chat.completion.chunk', created: 1, model: 'm', choices: [{ index: 0, delta, finish_reason: null, ...extra }] });

function runStream(mapping, events) {
  const r = createEventRestorer(mapping);
  return [...events.flatMap((e) => r.push(e)), ...r.flush()];
}
const joined = (events, pick) => events.map(pick).filter((x) => typeof x === 'string').join('');

test('PII-19: streamed content with a placeholder split across chunks is restored', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [
    chunk({ role: 'assistant', content: 'Dear [PER' }),
    chunk({ content: 'SON_1], your mail [EMA' }),
    chunk({ content: 'IL_1' }),
    chunk({ content: '] is set.' }),
    chunk({}, { finish_reason: 'stop' }),
    { id: 'gen-1', choices: [], usage: { prompt_tokens: 3 } },
  ]);
  const text = joined(out, (e) => e.choices?.[0]?.delta?.content);
  assert.equal(text, 'Dear Jane Roe, your mail jane.roe@example.com is set.');
  for (const e of out) assert.ok(!/\[[A-Z]+_?\d*$/.test(e.choices?.[0]?.delta?.content ?? ''), 'no partial placeholder emitted');
  assert.deepEqual(out.at(-1), { id: 'gen-1', choices: [], usage: { prompt_tokens: 3 } }, 'usage chunk passes through');
});

test('PII-27: streamed tool-call arguments are restored as valid JSON', () => {
  const m = { byPlaceholder: new Map([['[PERSON_1]', 'Jane "JR" Roe']]), grammar: { open: '[', close: ']' } };
  const out = runStream(m, [
    chunk({ tool_calls: [{ index: 0, id: 'c', type: 'function', function: { name: 'f', arguments: '{"who":"[PERS' } }] }),
    chunk({ tool_calls: [{ index: 0, function: { arguments: 'ON_1]"}' } }] }),
    chunk({}, { finish_reason: 'tool_calls' }),
  ]);
  const args = joined(out, (e) => e.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments);
  assert.deepEqual(JSON.parse(args), { who: 'Jane "JR" Roe' });
});

test('streamed tool-call arguments: bracket-stripped and \\u-escaped whiteSquare placeholders restore', () => {
  const m = { byPlaceholder: new Map([['⟦PERSON_1⟧', 'Jane "JR" Roe'], ['⟦EMAIL_1⟧', 'jane.roe@example.com']]), grammar: { open: '⟦', close: '⟧' } };
  const out = runStream(m, [
    chunk({ tool_calls: [{ index: 0, id: 'c', type: 'function', function: { name: 'f', arguments: '{"who":"PERS' } }] }),
    chunk({ tool_calls: [{ index: 0, function: { arguments: 'ON_1","to":"\\u27' } }] }),
    chunk({ tool_calls: [{ index: 0, function: { arguments: 'E6EMAIL_1\\u27e7"}' } }] }),
    chunk({}, { finish_reason: 'tool_calls' }),
  ]);
  const args = joined(out, (e) => e.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments);
  assert.deepEqual(JSON.parse(args), { who: 'Jane "JR" Roe', to: 'jane.roe@example.com' });
});

test('reasoning and content of the same choice are restored independently', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [
    chunk({ reasoning: 'think [PERS' }),
    chunk({ content: 'answer [ORG' }),
    chunk({ reasoning: 'ON_1]' }),
    chunk({ content: '_1]' }),
  ]);
  assert.equal(joined(out, (e) => e.choices[0].delta.reasoning), 'think Jane Roe');
  assert.equal(joined(out, (e) => e.choices[0].delta.content), 'answer Acme Corp');
});

test('PII-22: a held tail rides on the finish chunk, after that chunk\'s own text', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [chunk({ content: 'see [PERS' }), chunk({ content: 'x [PE' }, { finish_reason: 'length' })]);
  assert.equal(out.length, 2, 'no synthetic event needed');
  assert.equal(out[1].choices[0].delta.content, '[PERSx [PE');
  assert.equal(joined(out, (e) => e.choices[0].delta.content), 'see [PERSx [PE');
});

test('PII-22: stream cut without finish_reason — flush() emits a final delta with the tail', () => {
  const { mapping } = redact(REQUEST);
  const out = runStream(mapping, [chunk({ content: 'bye [PERSO' })]);
  assert.equal(out.length, 2);
  assert.deepEqual(out[1], { id: 'gen-1', object: 'chat.completion.chunk', created: 1, model: 'm', choices: [{ index: 0, delta: { content: '[PERSO' }, finish_reason: null }] });
});

test('multiple choices keep separate buffers', () => {
  const { mapping } = redact(REQUEST);
  const ev = (a, b) => ({ choices: [{ index: 0, delta: { content: a } }, { index: 1, delta: { content: b } }] });
  const out = runStream(mapping, [ev('A [PERS', 'B [ORG'), ev('ON_1]', '_1]')]);
  assert.equal(joined(out, (e) => e.choices[0].delta.content), 'A Jane Roe');
  assert.equal(joined(out, (e) => e.choices[1].delta.content), 'B Acme Corp');
});

test('events are not mutated', () => {
  const { mapping } = redact(REQUEST);
  const e = chunk({ content: '[PERSON_1]' });
  const before = JSON.stringify(e);
  createEventRestorer(mapping).push(e);
  assert.equal(JSON.stringify(e), before);
});

test('PII-20: non-stream response content and tool-call arguments are restored', () => {
  const { mapping } = redact(REQUEST);
  const body = {
    id: 'x', object: 'chat.completion',
    choices: [{ index: 0, finish_reason: 'tool_calls', message: {
      role: 'assistant', content: 'Hi [PERSON_1] of [ORG_1]; unknown [PERSON_9]', reasoning: 'r [EMAIL_1]',
      tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: '{"to":"[EMAIL_1]","n":"[PERSON_1]"}' } }],
    } }],
    usage: { total_tokens: 1 },
  };
  const out = restoreJson(body, mapping);
  const m = out.choices[0].message;
  assert.equal(m.content, 'Hi Jane Roe of Acme Corp; unknown [PERSON_9]');
  assert.equal(m.reasoning, 'r jane.roe@example.com');
  assert.deepEqual(JSON.parse(m.tool_calls[0].function.arguments), { to: 'jane.roe@example.com', n: 'Jane Roe' });
  assert.deepEqual(out.usage, body.usage);
  assert.ok(body.choices[0].message.content.includes('[PERSON_1]'), 'input not mutated');
});
