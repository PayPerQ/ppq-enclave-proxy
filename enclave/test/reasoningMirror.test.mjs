import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ReasoningMirror,
  MAX_LINE_CHARS,
  mirrorReasoningInto,
  mirrorReasoningLine,
  mirrorReasoningJson,
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
