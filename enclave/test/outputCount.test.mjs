import test from 'node:test';
import assert from 'node:assert/strict';

import { OutputCounter, MAX_COUNTED_CHARS, OVERFLOW_CHARS_PER_TOKEN, MAX_LINE_CHARS } from '../src/outputCount.mjs';
import { loadTokenizer } from '../src/inputEstimate.mjs';

const sse = (delta, extra = {}) =>
  `data: ${JSON.stringify({ id: 'gen-1', choices: [{ index: 0, delta, ...extra }] })}\n\n`;

test('counts content deltas with the o200k tokenizer', async () => {
  const c = new OutputCounter();
  c.feed(sse({ content: 'The quick brown fox ' }));
  c.feed(sse({ content: 'jumps over the lazy dog.' }));
  c.feed('data: [DONE]\n\n');
  const r = await c.finish();
  const count = await loadTokenizer();
  assert.equal(r.chars, 'The quick brown fox jumps over the lazy dog.'.length);
  assert.equal(r.tokens, count('The quick brown fox jumps over the lazy dog.'));
  assert.ok(r.tokens > 5);
});

test('reasoning and tool-call arguments are output too', async () => {
  const c = new OutputCounter();
  c.feed(sse({ reasoning: 'Let me think about railways. ' }));
  c.feed(sse({ reasoning_content: 'Fireworks shape. ' }));
  c.feed(sse({ tool_calls: [{ index: 0, function: { name: 'f', arguments: '{"q":"rail' } }] }));
  c.feed(sse({ tool_calls: [{ index: 0, function: { arguments: 'ways"}' } }] }));
  const r = await c.finish();
  const expected = 'Let me think about railways. Fireworks shape. {"q":"railways"}';
  assert.equal(r.chars, expected.length);
  assert.equal(r.tokens, (await loadTokenizer())(expected));
});

test('a chunk split across feeds and a usage frame with no delta are handled', async () => {
  const c = new OutputCounter();
  const line = sse({ content: 'split across two writes' });
  c.feed(Buffer.from(line.slice(0, 20)));
  c.feed(Buffer.from(line.slice(20)));
  c.feed(`data: ${JSON.stringify({ id: 'gen-1', choices: [], usage: { completion_tokens: 99 } })}\n\n`);
  c.feed(': keepalive comment\n\n');
  c.feed('data: not json at all\n\n');
  const r = await c.finish();
  assert.equal(r.chars, 'split across two writes'.length);
});

test('nothing delivered counts as zero, and finish drops the text', async () => {
  const c = new OutputCounter();
  c.feed(sse({ role: 'assistant' }));
  const r = await c.finish();
  assert.deepEqual(r, { chars: 0, tokens: 0 });
  assert.equal(c.text, '');
});

test('past the cap, characters are estimated by ratio instead of kept', async () => {
  const c = new OutputCounter();
  const big = 'a'.repeat(MAX_COUNTED_CHARS + 4000);
  // One oversized delta: only the cap's worth is retained for tokenizing.
  c._add(big);
  assert.equal(c.text.length, MAX_COUNTED_CHARS);
  assert.equal(c.overflowChars, 4000);
  const r = await c.finish();
  assert.equal(r.chars, big.length);
  assert.ok(r.tokens >= 4000 / OVERFLOW_CHARS_PER_TOKEN);
});

test('an unterminated line never grows the buffer past the line cap; counting resumes at the next newline', async () => {
  const c = new OutputCounter();
  c.feed(sse({ content: 'before ' }));
  // A line that never ends, delivered in pieces: dropped once it passes the cap.
  const piece = 'x'.repeat(200_000);
  for (let i = 0; i < 6; i++) c.feed('data: {"choices":[{"delta":{"content":"' + piece);
  assert.ok(c.buffer.length <= MAX_LINE_CHARS);
  assert.equal(c.skippingLine, true);
  assert.equal(c.droppedLines, 1);
  // Still skipping: more of the same line is ignored, buffer stays empty.
  c.feed(piece);
  assert.equal(c.buffer, '');
  // The newline ends the skip; the next well-formed chunk counts again.
  c.feed('"}}]}\n' + sse({ content: 'after' }));
  const r = await c.finish();
  assert.equal(r.chars, 'before after'.length);
});

test('a single oversized line arriving whole is dropped, not counted', async () => {
  const c = new OutputCounter();
  c.feed('data: ' + '{'.repeat(MAX_LINE_CHARS + 10) + '\n');
  c.feed(sse({ content: 'ok' }));
  const r = await c.finish();
  assert.equal(c.droppedLines, 1);
  assert.equal(r.chars, 2);
});
