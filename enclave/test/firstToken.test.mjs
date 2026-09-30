import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectFirstTokenKind, FirstTokenDetector } from '../src/firstToken.mjs';

const data = (obj) => `data: ${JSON.stringify(obj)}`;
const chat = (delta) => data({ id: 'gen-1', object: 'chat.completion.chunk', choices: [{ index: 0, delta }] });

// [label, line, expected kind]
const TABLE = [
  // ── not a data frame / carries nothing ──
  ['keep-alive comment', ': OPENROUTER PROCESSING', null],
  ['event line', 'event: content_block_delta', null],
  ['empty data', 'data: ', null],
  ['done sentinel', 'data: [DONE]', null],
  ['not JSON', 'data: hello', null],
  ['truncated JSON', 'data: {"choices":[{"delta":{"content":"hi"', null],
  ['JSON scalar', 'data: 42', null],
  ['not a string', undefined, null],

  // ── chat completions ──
  ['role-only delta', chat({ role: 'assistant' }), null],
  ['empty content', chat({ role: 'assistant', content: '' }), null],
  ['null content', chat({ content: null }), null],
  ['content text', chat({ content: 'Hello' }), 'content'],
  ['whitespace is still text', chat({ content: ' ' }), 'content'],
  ['reasoning', chat({ reasoning: 'Let me think' }), 'reasoning'],
  ['reasoning_content', chat({ reasoning_content: 'hmm' }), 'reasoning'],
  ['empty reasoning', chat({ reasoning: '', content: '' }), null],
  ['content wins over reasoning', chat({ reasoning: 'x', content: 'y' }), 'content'],
  ['tool call', chat({ tool_calls: [{ index: 0, id: 'call_1', function: { name: 'f', arguments: '' } }] }), 'content'],
  ['empty tool_calls', chat({ tool_calls: [] }), null],
  ['usage-only frame', data({ id: 'gen-1', choices: [], usage: { prompt_tokens: 3 } }), null],
  ['finish frame', data({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }), null],
  ['content on a later choice', data({ choices: [{ delta: {} }, { delta: { content: 'b' } }] }), 'content'],
  ['reasoning then content choices', data({ choices: [{ delta: { reasoning: 'r' } }, { delta: { content: 'c' } }] }), 'content'],
  ['no leading space after data:', 'data:' + JSON.stringify({ choices: [{ delta: { content: 'x' } }] }), 'content'],

  // ── Anthropic Messages ──
  ['message_start', data({ type: 'message_start', message: { id: 'msg_1', usage: { input_tokens: 3 } } }), null],
  ['text block start', data({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }), null],
  ['thinking block start', data({ type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '' } }), null],
  ['tool_use block start', data({ type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't', name: 'f', input: {} } }), 'content'],
  ['text_delta', data({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hi' } }), 'content'],
  ['empty text_delta', data({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '' } }), null],
  ['thinking_delta', data({ type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'hm' } }), 'reasoning'],
  ['signature_delta', data({ type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: 'abc' } }), null],
  ['input_json_delta', data({ type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{"a"' } }), 'content'],
  ['ping', data({ type: 'ping' }), null],
  ['message_delta', data({ type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 } }), null],

  // ── OpenAI Responses ──
  ['response.created', data({ type: 'response.created', response: { id: 'resp_1' } }), null],
  ['output_item.added', data({ type: 'response.output_item.added', item: { type: 'message' } }), null],
  ['output_text.delta', data({ type: 'response.output_text.delta', delta: 'Hi' }), 'content'],
  ['empty output_text.delta', data({ type: 'response.output_text.delta', delta: '' }), null],
  ['function_call_arguments.delta', data({ type: 'response.function_call_arguments.delta', delta: '{' }), 'content'],
  ['reasoning_summary_text.delta', data({ type: 'response.reasoning_summary_text.delta', delta: 'x' }), 'reasoning'],
  ['reasoning_text.delta', data({ type: 'response.reasoning_text.delta', delta: 'x' }), 'reasoning'],
  ['response.completed', data({ type: 'response.completed', response: { usage: { output_tokens: 3 } } }), null],
];

test('first-token kind, per frame shape', () => {
  for (const [label, line, expected] of TABLE) {
    assert.equal(detectFirstTokenKind(line), expected, label);
  }
});

test('detector: keep-alives and role-only deltas never count; the first text frame does', () => {
  const d = new FirstTokenDetector();
  const enc = (s) => Buffer.from(s);
  assert.equal(d.feed(enc(': OPENROUTER PROCESSING\n\n')), null);
  assert.equal(d.feed(enc(chat({ role: 'assistant', content: '' }) + '\n\n')), null);
  assert.equal(d.feed(enc(chat({ reasoning: 'thinking' }) + '\n\n')), 'reasoning');
  // Found once: every later frame, even a content one, reports nothing.
  assert.equal(d.feed(enc(chat({ content: 'answer' }) + '\n\n')), null);
  assert.equal(d.done, true);
});

test('detector: a frame split across chunks (and a multi-byte char split mid-sequence) is joined', () => {
  const whole = Buffer.from(chat({ content: 'héllo' }) + '\r\n\r\n');
  const cut = whole.indexOf(Buffer.from('é')) + 1; // inside the two-byte é
  const d = new FirstTokenDetector();
  assert.equal(d.feed(whole.subarray(0, 7)), null);
  assert.equal(d.feed(whole.subarray(7, cut)), null);
  assert.equal(d.feed(whole.subarray(cut)), 'content');
});

test('detector: several frames in one chunk stop at the first token-bearing one', () => {
  const d = new FirstTokenDetector();
  const chunk = [
    ': keep-alive',
    '',
    'event: content_block_start',
    data({ type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '' } }),
    '',
    'event: content_block_delta',
    data({ type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'a' } }),
    '',
    data({ type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'b' } }),
    '',
  ].join('\n');
  assert.equal(d.feed(Buffer.from(chunk)), 'reasoning');
});

test('detector: a line that never ends is abandoned past the bound, not held forever', () => {
  const d = new FirstTokenDetector();
  const block = Buffer.alloc(256 * 1024, 'a');
  for (let i = 0; i < 5; i++) d.feed(block);
  assert.equal(d.done, true);
  assert.equal(d.pending, '');
  assert.equal(d.feed(Buffer.from(chat({ content: 'late' }) + '\n')), null);
});

test('detector: after the first token it does no work at all (O(1) per chunk)', () => {
  const d = new FirstTokenDetector();
  assert.equal(d.feed(Buffer.from(chat({ content: 'x' }) + '\n')), 'content');
  // Count every parse and decode the rest of the stream would cost.
  const realParse = JSON.parse;
  const realDecode = d.decoder.decode;
  let parses = 0;
  let decodes = 0;
  JSON.parse = (...a) => { parses++; return realParse(...a); };
  d.decoder.decode = (...a) => { decodes++; return realDecode.apply(d.decoder, a); };
  try {
    const frame = Buffer.from((chat({ content: 'more text' }) + '\n\n').repeat(50));
    for (let i = 0; i < 1000; i++) assert.equal(d.feed(frame), null);
  } finally {
    JSON.parse = realParse;
    d.decoder.decode = realDecode;
  }
  assert.equal(parses, 0);
  assert.equal(decodes, 0);
  assert.equal(d.pending, '');
});

test('detector: the search before the first token stays far inside the latency budget', () => {
  // Budget: the whole feature may add at most 5 ms to time-to-first-token at
  // p90. A long reasoning-free preamble (1000 keep-alive / role-only frames)
  // must cost a small fraction of that per frame.
  const pre = Buffer.from(': keep-alive\n\n' + chat({ role: 'assistant', content: '' }) + '\n\n');
  const d = new FirstTokenDetector();
  const t0 = performance.now();
  for (let i = 0; i < 1000; i++) d.feed(pre);
  const kind = d.feed(Buffer.from(chat({ content: 'x' }) + '\n'));
  const perFrameMs = (performance.now() - t0) / 1001;
  assert.equal(kind, 'content');
  assert.ok(perFrameMs < 0.5, `per-frame cost ${perFrameMs.toFixed(4)} ms`);
});
