import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ReasoningMirror,
  MAX_LINE_CHARS,
  MAX_JSON_BODY_BYTES,
  mirrorReasoningInto,
  mirrorReasoningLine,
  mirrorReasoningJson,
  liftVertexThought,
  THOUGHT_FLAG,
  REASONING_MIRROR_PROVIDERS,
} from '../src/reasoningMirror.mjs';

const sse = (delta, extra = {}) =>
  `data: ${JSON.stringify({ id: 'x', model: 'accounts/fireworks/models/kimi-k3', choices: [{ index: 0, delta, ...extra }] })}\n\n`;

const run = (m, chunks) => {
  let out = '';
  for (const c of chunks) out += m.feed(Buffer.from(c, 'utf8')).toString('utf8');
  out += m.finish().toString('utf8');
  return out;
};

const deltasOf = (text) =>
  text
    .split('\n')
    .filter((l) => l.startsWith('data: {'))
    .map((l) => JSON.parse(l.slice(6)))
    .filter((c) => c.choices?.[0]?.delta !== undefined)
    .map((c) => c.choices[0].delta);

test('mirrorReasoningInto: reasoning_content → reasoning + reasoning_details, content kept', () => {
  const d = { reasoning_content: 'think' };
  assert.equal(mirrorReasoningInto(d), true);
  assert.deepEqual(d, {
    reasoning_content: 'think',
    reasoning: 'think',
    reasoning_details: [{ type: 'reasoning.text', text: 'think', format: 'unknown', index: 0 }],
  });
});

test('mirrorReasoningInto: never overwrites an upstream reasoning / reasoning_details', () => {
  const d = { reasoning_content: 'a', reasoning: 'b', reasoning_details: [] };
  assert.equal(mirrorReasoningInto(d), false);
  assert.deepEqual(d, { reasoning_content: 'a', reasoning: 'b', reasoning_details: [] });
});

test('mirrorReasoningInto: a null upstream reasoning is filled, empty text gets no details', () => {
  const d = { reasoning_content: '', reasoning: null };
  assert.equal(mirrorReasoningInto(d), true);
  assert.deepEqual(d, { reasoning_content: '', reasoning: '' });
});

test('mirrorReasoningInto: no-op without reasoning_content or on a non-object', () => {
  const d = { content: 'hi' };
  assert.equal(mirrorReasoningInto(d), false);
  assert.deepEqual(d, { content: 'hi' });
  assert.equal(mirrorReasoningInto(null), false);
  assert.equal(mirrorReasoningInto('x'), false);
  assert.equal(mirrorReasoningInto([{ reasoning_content: 'x' }]), false);
});

test('mirrorReasoningLine: passes comments, [DONE], errors and content chunks through byte-identical', () => {
  for (const line of [
    ': keep-alive',
    'data: [DONE]',
    'data: {"error":{"message":"boom"}}',
    'data: {"choices":[{"delta":{"content":"hi"}}]}',
    'event: ping',
    '',
    'data: not json reasoning_content',
  ]) {
    assert.equal(mirrorReasoningLine(line), line);
  }
});

test('mirrorReasoningLine: a line over MAX_LINE_CHARS is untouched', () => {
  const line = `data: {"choices":[{"delta":{"reasoning_content":"${'x'.repeat(MAX_LINE_CHARS)}"}}]}`;
  assert.equal(mirrorReasoningLine(line), line);
});

test('ReasoningMirror (sse): mirrors across chunk boundaries and keeps framing', () => {
  const m = new ReasoningMirror({ sse: true });
  const a = sse({ role: 'assistant', reasoning_content: 'Let me ' });
  const b = sse({ reasoning_content: 'think.' });
  const c = sse({ content: 'Answer.' }, { finish_reason: 'stop' });
  const usage = `data: ${JSON.stringify({ choices: [], usage: { completion_tokens: 3, completion_tokens_details: { reasoning_tokens: 2 } } })}\n\n`;
  const out = run(m, [a.slice(0, 20), a.slice(20) + b.slice(0, 5), b.slice(5) + c, usage, 'data: [DONE]\n\n']);
  const deltas = deltasOf(out);
  assert.equal(deltas.length, 3);
  assert.equal(deltas[0].reasoning, 'Let me ');
  assert.equal(deltas[0].reasoning_content, 'Let me ');
  assert.deepEqual(deltas[0].reasoning_details, [
    { type: 'reasoning.text', text: 'Let me ', format: 'unknown', index: 0 },
  ]);
  assert.equal(deltas[1].reasoning, 'think.');
  assert.equal(deltas[2].reasoning, undefined);
  assert.equal(deltas[2].content, 'Answer.');
  assert.ok(out.endsWith('data: [DONE]\n\n'));
  assert.ok(out.includes(usage), 'usage frame passes through byte-identical');
  // Every frame still terminated by the blank line.
  assert.equal(out.split('\n\n').length - 1, 5);
});

test('ReasoningMirror (sse): a stream without reasoning_content is byte-identical', () => {
  const m = new ReasoningMirror({ sse: true });
  const input = [': OPENROUTER PROCESSING\n\n', sse({ content: 'a' }), sse({ content: 'b' }, { finish_reason: 'stop' }), 'data: [DONE]\n\n'];
  assert.equal(run(m, input), input.join(''));
});

test('ReasoningMirror (sse): CRLF line endings are preserved', () => {
  const m = new ReasoningMirror({ sse: true });
  const line = `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: 'r' } }] })}\r\n\r\n`;
  const out = run(m, [line]);
  assert.ok(out.endsWith('\r\n\r\n'));
  assert.equal(JSON.parse(out.split('\r\n')[0].slice(6)).choices[0].delta.reasoning, 'r');
});

test('ReasoningMirror (sse): an overlong partial line is released raw and the stream continues', () => {
  const m = new ReasoningMirror({ sse: true });
  const huge = `data: {"choices":[{"delta":{"reasoning_content":"${'y'.repeat(MAX_LINE_CHARS + 10)}"}}]}\n\n`;
  const after = sse({ reasoning_content: 'ok' });
  const out = run(m, [huge.slice(0, MAX_LINE_CHARS + 50), huge.slice(MAX_LINE_CHARS + 50), after]);
  assert.ok(out.startsWith(huge), 'the huge line went out untouched');
  const last = deltasOf(out.slice(huge.length));
  assert.equal(last.length, 1);
  assert.equal(last[0].reasoning, 'ok');
});

test('ReasoningMirror (json): holds the body and mirrors message.reasoning_content once', () => {
  const m = new ReasoningMirror({ sse: false });
  const body = JSON.stringify({
    id: 'x',
    choices: [{ index: 0, message: { role: 'assistant', content: 'Answer', reasoning_content: 'why' }, finish_reason: 'stop' }],
    usage: { completion_tokens: 5 },
  });
  const first = m.feed(Buffer.from(body.slice(0, 30), 'utf8'));
  assert.equal(first.length, 0, 'nothing forwarded before the body is complete');
  const out = (Buffer.concat([m.feed(Buffer.from(body.slice(30), 'utf8')), m.finish()])).toString('utf8');
  const parsed = JSON.parse(out);
  assert.equal(parsed.choices[0].message.reasoning, 'why');
  assert.equal(parsed.choices[0].message.reasoning_content, 'why');
  assert.equal(parsed.choices[0].message.reasoning_details[0].text, 'why');
  assert.equal(parsed.usage.completion_tokens, 5);
});

test('ReasoningMirror (json): a body without reasoning_content is byte-identical', () => {
  const m = new ReasoningMirror({ sse: false });
  const body = '{"choices":[{"message":{"role":"assistant","content":"hi"}}]}';
  assert.equal(run(m, [body]), body);
});

test('ReasoningMirror (json): the cap is measured in UTF-8 bytes, and past it the body passes through raw', () => {
  // ~6M CJK characters = ~18 MB UTF-8: under a 16M CHARACTER cap, over the BYTE cap.
  const cjk = '思'.repeat(6_000_000);
  const body = `{"choices":[{"message":{"reasoning_content":"${cjk}"}}]}`;
  assert.ok(body.length < MAX_JSON_BODY_BYTES);
  assert.ok(Buffer.byteLength(body, 'utf8') > MAX_JSON_BODY_BYTES);
  assert.equal(mirrorReasoningJson(body), body);
  const m = new ReasoningMirror({ sse: false });
  const bytes = Buffer.from(body, 'utf8');
  const half = bytes.length >> 1;
  const first = m.feed(bytes.subarray(0, half));
  assert.equal(first.length, 0, 'still buffering under the byte cap');
  const rest = Buffer.concat([m.feed(bytes.subarray(half)), m.finish()]);
  assert.equal(Buffer.concat([first, rest]).toString('utf8'), body, 'released raw, byte-identical');
});

test('mirrorReasoningJson: malformed JSON passes through', () => {
  const body = '{"choices":[{"message":{"reasoning_content":"x"';
  assert.equal(mirrorReasoningJson(body), body);
});

test('ReasoningMirror (json): multi-byte UTF-8 split across chunks survives', () => {
  const m = new ReasoningMirror({ sse: false });
  const body = JSON.stringify({ choices: [{ message: { reasoning_content: 'Überlegung — 思考' } }] });
  const bytes = Buffer.from(body, 'utf8');
  const cut = bytes.indexOf(Buffer.from('思', 'utf8')) + 1; // inside a 3-byte sequence
  const out = Buffer.concat([m.feed(bytes.subarray(0, cut)), m.feed(bytes.subarray(cut)), m.finish()]).toString('utf8');
  assert.equal(JSON.parse(out).choices[0].message.reasoning, 'Überlegung — 思考');
});

// ── Vertex thoughts (#432) ───────────────────────────────────────────────────

const thought = (text) => ({ content: text, role: 'assistant', extra_content: { google: { thought: true } } });
const vsse = (delta, extra = {}) =>
  `data: ${JSON.stringify({ id: 'v', model: 'google/gemini-4-carbon', object: 'chat.completion.chunk', choices: [{ index: 0, delta, logprobs: null, ...extra }] })}\n\n`;

test('liftVertexThought: a flagged delta moves its content into reasoning_content and leaves content empty', () => {
  const d = thought('**Planning**\n\nFirst I will…');
  assert.equal(liftVertexThought(d), true);
  assert.deepEqual(d, {
    content: '',
    role: 'assistant',
    reasoning_content: '**Planning**\n\nFirst I will…',
    extra_content: { google: { thought: true } },
  });
});

test('liftVertexThought: no-op without the flag, on a non-string content, or when reasoning_content is already set', () => {
  for (const part of [
    { content: 'answer' },
    { content: 'answer', extra_content: { google: { thought: false } } },
    { content: 'sig', extra_content: { google: { thought_signature: 'AY89' } } },
    { content: null, extra_content: { google: { thought: true } } },
    { content: 'x', reasoning_content: 'kept', extra_content: { google: { thought: true } } },
    null,
    'str',
  ]) {
    const before = JSON.stringify(part);
    assert.equal(liftVertexThought(part), false);
    assert.equal(JSON.stringify(part), before);
  }
});

test('liftVertexThought: a non-streaming message splits its <think> prefix from the answer', () => {
  const m = thought('<think>\n**Deep dive**\n\nBecause Rayleigh.</think>\n\nThe sky is blue.');
  assert.equal(liftVertexThought(m), true);
  assert.equal(m.reasoning_content, '**Deep dive**\n\nBecause Rayleigh.');
  assert.equal(m.content, 'The sky is blue.');
  // An unclosed tag is not a prefix: the whole content is the thought.
  const open = thought('<think>\nstill thinking');
  assert.equal(liftVertexThought(open), true);
  assert.equal(open.reasoning_content, '<think>\nstill thinking');
  assert.equal(open.content, '');
});

test('mirrorReasoningInto: a flagged Vertex delta ends in the OpenRouter shape', () => {
  const d = thought('why');
  assert.equal(mirrorReasoningInto(d), true);
  assert.deepEqual(d, {
    content: '',
    role: 'assistant',
    reasoning_content: 'why',
    reasoning: 'why',
    reasoning_details: [{ type: 'reasoning.text', text: 'why', format: 'unknown', index: 0 }],
    extra_content: { google: { thought: true } },
  });
});

test('ReasoningMirror (sse): a Vertex stream — thoughts lifted, answer and signature chunks byte-identical', () => {
  const sig = vsse({ content: '', extra_content: { google: { thought_signature: 'AY89abc' } } }, { finish_reason: 'stop' });
  const answer = vsse({ content: 'The sky is blue.', role: 'assistant' });
  const text = vsse(thought('**Plan**')) + vsse(thought(' then act')) + answer + sig + 'data: [DONE]\n\n';
  const out = run(new ReasoningMirror({ sse: true }), [text.slice(0, 40), text.slice(40, 41), text.slice(41)]);
  const deltas = deltasOf(out);
  assert.deepEqual(deltas[0], {
    content: '',
    role: 'assistant',
    reasoning_content: '**Plan**',
    reasoning: '**Plan**',
    reasoning_details: [{ type: 'reasoning.text', text: '**Plan**', format: 'unknown', index: 0 }],
    extra_content: { google: { thought: true } },
  });
  assert.equal(deltas[1].reasoning, ' then act');
  assert.ok(out.includes(answer), 'answer chunk untouched');
  assert.ok(out.includes(sig), 'signature chunk untouched');
  assert.ok(out.endsWith('data: [DONE]\n\n'));
  assert.ok(THOUGHT_FLAG.test(text));
});

test('ReasoningMirror (json): a Vertex body has its <think> prefix lifted once', () => {
  const body = JSON.stringify({
    id: 'v',
    choices: [{ index: 0, message: thought('<think>\nwhy</think>\n\nBlue.'), finish_reason: 'stop' }],
    usage: { completion_tokens: 3, completion_tokens_details: { reasoning_tokens: 2 } },
  });
  const out = run(new ReasoningMirror({ sse: false }), [body.slice(0, 20), body.slice(20)]);
  const msg = JSON.parse(out).choices[0].message;
  assert.equal(msg.content, 'Blue.');
  assert.equal(msg.reasoning, 'why');
  assert.equal(msg.reasoning_content, 'why');
  assert.deepEqual(JSON.parse(out).usage, { completion_tokens: 3, completion_tokens_details: { reasoning_tokens: 2 } });
});

test('Vertex thoughts: the flag is read in any JSON spacing, and the mirror set names vertex (#432)', () => {
  const spaced = 'data: {"choices":[{"index":0,"delta":{"content":"why","extra_content":{"google":{"thought" : true}}}}]}';
  const d = JSON.parse(mirrorReasoningLine(spaced).slice(6)).choices[0].delta;
  assert.equal(d.reasoning, 'why');
  assert.equal(d.content, '');
  assert.equal(THOUGHT_FLAG.test('"thought": false'), false);
  assert.deepEqual([...REASONING_MIRROR_PROVIDERS].sort(), ['fireworks', 'foundry', 'vertex']);
});
