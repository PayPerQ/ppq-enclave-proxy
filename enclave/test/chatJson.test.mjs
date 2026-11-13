// chatJson.mjs (#411): one chat.completion from a chat-completions event
// stream, for a caller that did not ask for a stream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ChatSseToJson,
  DEFAULT_KEEPALIVE_MS,
  MAX_KEEPALIVE_MS,
  MAX_LINE_CHARS,
  MIN_KEEPALIVE_MS,
  RECORD_CHARS,
  keepaliveIntervalMs,
} from '../src/chatJson.mjs';

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const chunk = (delta, extra = {}) => ({
  id: 'gen-1',
  object: 'chat.completion.chunk',
  created: 1793850000,
  model: 'moonshotai/kimi-k3',
  provider: 'Fireworks',
  choices: [{ index: 0, delta, finish_reason: null, ...extra }],
});

function assemble(text, opts) {
  const a = new ChatSseToJson(opts);
  a.feed(Buffer.from(text, 'utf8'));
  return JSON.parse(a.finish().toString('utf8'));
}

test('content deltas, the finish reason and the usage frame become one chat.completion', () => {
  const stream =
    ': ppq-routing-receipt {"v":3}\n\n' +
    sse(chunk({ role: 'assistant', content: 'Hel' })) +
    sse(chunk({ content: 'lo' })) +
    sse({ ...chunk({}), choices: [{ index: 0, delta: {}, finish_reason: 'stop', native_finish_reason: 'stop' }] }) +
    sse({ id: 'gen-1', object: 'chat.completion.chunk', model: 'moonshotai/kimi-k3', choices: [], usage: { prompt_tokens: 11, completion_tokens: 2, total_tokens: 13 } }) +
    'data: [DONE]\n\n';
  const out = assemble(stream);
  assert.deepEqual(out, {
    id: 'gen-1',
    object: 'chat.completion',
    created: 1793850000,
    model: 'moonshotai/kimi-k3',
    provider: 'Fireworks',
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content: 'Hello' },
        finish_reason: 'stop',
        logprobs: null,
        native_finish_reason: 'stop',
      },
    ],
    usage: { prompt_tokens: 11, completion_tokens: 2, total_tokens: 13 },
  });
});

test('a stream fed one byte at a time, with CRLF line ends, assembles the same answer', () => {
  const stream = (sse(chunk({ content: 'a' })) + sse(chunk({ content: 'b' })) + sse(chunk({ content: 'c' }, { finish_reason: 'stop' }))).replace(/\n/g, '\r\n');
  const a = new ChatSseToJson();
  for (const byte of Buffer.from(stream, 'utf8')) a.feed(Buffer.from([byte]));
  const out = JSON.parse(a.finish().toString('utf8'));
  assert.equal(out.choices[0].message.content, 'abc');
  assert.equal(out.choices[0].finish_reason, 'stop');
});

test('tool calls merge by index with their arguments joined; content stays null without text', () => {
  const stream =
    sse(chunk({ role: 'assistant', tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'get_weather', arguments: '' } }] })) +
    sse(chunk({ tool_calls: [{ index: 0, function: { arguments: '{"city":' } }] })) +
    sse(chunk({ tool_calls: [{ index: 0, function: { arguments: '"Berlin"}' } }, { index: 1, id: 'call_2', type: 'function', function: { name: 'get_time', arguments: '{}' } }] })) +
    sse({ ...chunk({}), choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] });
  const out = assemble(stream);
  const msg = out.choices[0].message;
  assert.equal(msg.content, null);
  assert.deepEqual(msg.tool_calls, [
    { index: 0, id: 'call_1', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Berlin"}' } },
    { index: 1, id: 'call_2', type: 'function', function: { name: 'get_time', arguments: '{}' } },
  ]);
  assert.equal(out.choices[0].finish_reason, 'tool_calls');
});

test('reasoning text concatenates and reasoning_details entries that continue each other are one entry', () => {
  // The Fireworks mirror's per-delta shape (reasoningMirror.mjs): the same
  // type/index/format on every delta, which the assembled answer joins.
  const detail = (text) => ({ type: 'reasoning.text', text, format: 'unknown', index: 0 });
  const stream =
    sse(chunk({ reasoning_content: 'th', reasoning: 'th', reasoning_details: [detail('th')] })) +
    sse(chunk({ reasoning_content: 'ink', reasoning: 'ink', reasoning_details: [detail('ink')] })) +
    sse(chunk({ reasoning_details: [{ type: 'reasoning.encrypted', data: 'abc', index: 1 }] })) +
    sse(chunk({ content: 'answer' }, { finish_reason: 'stop' }));
  const msg = assemble(stream).choices[0].message;
  assert.equal(msg.reasoning, 'think');
  assert.equal(msg.reasoning_content, 'think');
  assert.deepEqual(msg.reasoning_details, [
    { type: 'reasoning.text', text: 'think', format: 'unknown', index: 0 },
    { type: 'reasoning.encrypted', data: 'abc', index: 1 },
  ]);
  assert.equal(msg.content, 'answer');
});

test('n > 1: choices are kept apart by index and ordered', () => {
  const two = (i, content, finish) => ({ ...chunk({}), choices: [{ index: i, delta: { content }, finish_reason: finish ?? null }] });
  const stream = sse(two(1, 'B1')) + sse(two(0, 'A1')) + sse(two(1, 'B2', 'stop')) + sse(two(0, 'A2', 'length'));
  const out = assemble(stream);
  assert.deepEqual(out.choices.map((c) => [c.index, c.message.content, c.finish_reason]), [
    [0, 'A1A2', 'length'],
    [1, 'B1B2', 'stop'],
  ]);
});

test('annotations and top-level citations accumulate', () => {
  const stream =
    sse({ ...chunk({ content: 'see' }), citations: ['https://a.example'] }) +
    sse({ ...chunk({ annotations: [{ type: 'url_citation', url_citation: { url: 'https://a.example' } }] }), citations: ['https://a.example', 'https://b.example'] }) +
    sse(chunk({ annotations: [{ type: 'url_citation', url_citation: { url: 'https://b.example' } }] }, { finish_reason: 'stop' }));
  const out = assemble(stream);
  assert.deepEqual(out.citations, ['https://a.example', 'https://b.example']);
  assert.equal(out.choices[0].message.annotations.length, 2);
});

test('an in-band error frame is kept on the answer, as a JSON answer would carry it', () => {
  const stream =
    sse(chunk({ content: 'par' })) +
    sse({ id: 'gen-1', object: 'chat.completion.chunk', error: { message: 'Provider returned error', code: 502 }, choices: [{ index: 0, delta: {}, finish_reason: 'error' }] });
  const out = assemble(stream);
  assert.equal(out.choices[0].message.content, 'par');
  assert.equal(out.choices[0].finish_reason, 'error');
  assert.deepEqual(out.error, { message: 'Provider returned error', code: 502 });
});

test('a stream with no completion frame is an error object, not an empty completion', () => {
  assert.deepEqual(assemble(': only a comment\n\ndata: [DONE]\n\n'), {
    error: { message: 'upstream stream carried no completion', code: 502 },
  });
  assert.deepEqual(assemble(''), { error: { message: 'upstream stream carried no completion', code: 502 } });
  // An error frame alone is that error.
  assert.deepEqual(assemble(sse({ error: { message: 'nope', code: 429 } })), { error: { message: 'nope', code: 429 } });
});

test('frames that are not JSON are skipped, not fatal', () => {
  const stream = sse(chunk({ content: 'ok' }, { finish_reason: 'stop' })) + 'data: {not json\n\n' + 'event: ping\n\n';
  const a = new ChatSseToJson();
  a.feed(Buffer.from(stream, 'utf8'));
  const out = JSON.parse(a.finish().toString('utf8'));
  assert.equal(out.choices[0].message.content, 'ok');
  assert.equal(a.unparsed, 1);
  assert.equal(a.frames, 1);
});

test('past the text bound the answer is an error object and nothing more is held', () => {
  const a = new ChatSseToJson({ maxChars: 10 });
  a.feed(Buffer.from(sse(chunk({ content: 'twelve chars' })), 'utf8'));
  assert.equal(a.overflow, true);
  a.feed(Buffer.from(sse(chunk({ content: 'more' })), 'utf8'));
  assert.deepEqual(JSON.parse(a.finish().toString('utf8')), {
    error: { message: 'upstream response too large to assemble', code: 502 },
  });
});

test('the keepalive interval defaults and clamps', () => {
  assert.equal(keepaliveIntervalMs(undefined), DEFAULT_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs(''), DEFAULT_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs('abc'), DEFAULT_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs('0'), DEFAULT_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs('-5'), DEFAULT_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs('1'), MIN_KEEPALIVE_MS);
  assert.equal(keepaliveIntervalMs('250'), 250);
  assert.equal(keepaliveIntervalMs('999999'), MAX_KEEPALIVE_MS);
});

test('`failed` names an answer that is an error object, and only that', () => {
  const ok = new ChatSseToJson();
  ok.feed(Buffer.from(sse(chunk({ content: 'fine' }, { finish_reason: 'stop' })), 'utf8'));
  ok.finish();
  assert.equal(ok.failed, false);
  assert.equal(ok.failureReason, null);

  const none = new ChatSseToJson();
  none.feed(Buffer.from(sse({ error: { message: 'nope', code: 429 } }), 'utf8'));
  none.finish();
  assert.equal(none.failed, true);
  assert.equal(none.failureReason, 'no_completion');

  const over = new ChatSseToJson({ maxChars: 4 });
  over.feed(Buffer.from(sse(chunk({ content: 'too long' })), 'utf8'));
  over.finish();
  assert.equal(over.failed, true);
  assert.equal(over.failureReason, 'overflow');

  // A partial answer followed by an in-band error is still an answer (the
  // streamed client would have received both): not `failed`.
  const partial = new ChatSseToJson();
  partial.feed(Buffer.from(sse(chunk({ content: 'par' })) + sse({ error: { message: 'cut', code: 502 } }), 'utf8'));
  partial.finish();
  assert.equal(partial.failed, false);
});

test('a data line longer than MAX_LINE_CHARS is dropped, never buffered, and the stream goes on', () => {
  const a = new ChatSseToJson();
  const huge = 'data: {"choices":[{"index":0,"delta":{"content":"' + 'x'.repeat(MAX_LINE_CHARS + 10);
  // Fed in pieces with no newline: the carry is cut the moment it passes the bound.
  for (let i = 0; i < huge.length; i += 200_000) a.feed(Buffer.from(huge.slice(i, i + 200_000), 'utf8'));
  assert.ok(a.carry.length <= MAX_LINE_CHARS, `carry bounded: ${a.carry.length}`);
  assert.equal(a.skippingLine, true);
  a.feed(Buffer.from('"}}]}\n\n' + sse(chunk({ content: 'after' }, { finish_reason: 'stop' })), 'utf8'));
  const out = JSON.parse(a.finish().toString('utf8'));
  assert.equal(out.choices[0].message.content, 'after');
  assert.equal(a.unparsed, 1);
  assert.equal(a.failed, false);
});

test('arrays and objects merged whole count against the bound too', () => {
  const a = new ChatSseToJson({ maxChars: 200 });
  const big = { type: 'url_citation', url_citation: { url: 'https://example.com/' + 'a'.repeat(300) } };
  a.feed(Buffer.from(sse(chunk({ content: 'x', annotations: [big] })), 'utf8'));
  assert.equal(a.overflow, true);
  assert.equal(a.failureReason, 'overflow');

  const l = new ChatSseToJson({ maxChars: 200 });
  l.feed(Buffer.from(sse({ ...chunk({ content: 'x' }), choices: [{ index: 0, delta: { content: 'x' }, logprobs: { content: Array.from({ length: 40 }, (_, i) => ({ token: 't' + i, logprob: -0.1 })) } }] }), 'utf8'));
  assert.equal(l.overflow, true);
});

test('a `__proto__` member on a frame never reaches Object.prototype', () => {
  const polluted = () => ({}).polluted !== undefined || ({}).hacked !== undefined;
  const a = new ChatSseToJson();
  const frames = [
    'data: {"id":"gen-1","__proto__":{"polluted":1},"choices":[{"index":0,"delta":{"content":"a","__proto__":{"polluted":1}},"logprobs":{"__proto__":{"polluted":1}}}]}\n\n',
    // A delta whose record field is then merged with Object.assign: the key is skipped before it gets there.
    'data: {"choices":[{"index":0,"delta":{"extra":{"x":1}}}]}\n\n',
    'data: {"choices":[{"index":0,"delta":{"extra":{"__proto__":{"hacked":1}},"reasoning_details":[{"type":"reasoning.text","text":"t","__proto__":{"hacked":1}}]},"finish_reason":"stop"}]}\n\n',
  ];
  for (const f of frames) a.feed(Buffer.from(f, 'utf8'));
  const out = JSON.parse(a.finish().toString('utf8'));
  assert.equal(polluted(), false, 'Object.prototype untouched');
  assert.equal(out.choices[0].message.content, 'a');
  assert.equal(Object.hasOwn(out, '__proto__'), false);
  assert.equal(Object.hasOwn(out.choices[0].message, '__proto__'), false);
  assert.equal(Object.hasOwn(out.choices[0].message.reasoning_details[0], '__proto__'), false);
});

test('a tool-call answer whose only content delta was the translators\' empty opener is content: null', () => {
  const stream =
    sse(chunk({ role: 'assistant', content: '' })) +
    sse(chunk({ tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'f', arguments: '{}' } }] }, { finish_reason: 'tool_calls' }));
  const msg = assemble(stream).choices[0].message;
  assert.equal(msg.content, null);
  assert.equal(msg.tool_calls.length, 1);
  // An empty text answer with no tool calls keeps '' (that is what was generated).
  assert.equal(assemble(sse(chunk({ role: 'assistant', content: '' }, { finish_reason: 'stop' }))).choices[0].message.content, '');
});

test('data lines that never reach a blank line are bounded before they are held (CodeRabbit on #449)', () => {
  const a = new ChatSseToJson();
  // Short `data:` lines with no event delimiter: each one alone is well under
  // MAX_LINE_CHARS, together they would grow dataLines without bound.
  const line = 'data: ' + 'y'.repeat(1_000) + '\n';
  const perFeed = line.repeat(100);
  for (let fed = 0; fed <= MAX_LINE_CHARS + 200_000; fed += perFeed.length) a.feed(Buffer.from(perFeed, 'utf8'));
  assert.equal(a.skippingEvent, true, 'the never-ending event is being discarded');
  assert.equal(a.dataLines.length, 0, 'nothing of it is held');
  assert.ok(a.pendingChars <= MAX_LINE_CHARS, `pending bounded: ${a.pendingChars}`);
  // The blank line ends the discarded event; the stream goes on.
  a.feed(Buffer.from('\n' + sse(chunk({ content: 'after' }, { finish_reason: 'stop' })), 'utf8'));
  const out = JSON.parse(a.finish().toString('utf8'));
  assert.equal(out.choices[0].message.content, 'after');
  assert.equal(a.unparsed, 1);
  assert.equal(a.failed, false);
});

test('new choice and tool-call records, and tool names, count against the bound (CodeRabbit on #449)', () => {
  // Distinct indexes with empty deltas: no text, yet every frame allocates.
  const choices = new ChatSseToJson({ maxChars: RECORD_CHARS * 10 });
  for (let i = 0; i < 20 && !choices.overflow; i++) {
    choices.feed(Buffer.from(sse({ ...chunk({}), choices: [{ index: i, delta: {} }] }), 'utf8'));
  }
  assert.equal(choices.overflow, true, 'choice records are charged');
  assert.equal(choices.failed, true);

  const tools = new ChatSseToJson({ maxChars: RECORD_CHARS * 10 });
  for (let i = 0; i < 20 && !tools.overflow; i++) {
    tools.feed(Buffer.from(sse(chunk({ tool_calls: [{ index: i, type: 'function', function: { name: '', arguments: '' } }] })), 'utf8'));
  }
  assert.equal(tools.overflow, true, 'tool-call records are charged');

  const names = new ChatSseToJson({ maxChars: RECORD_CHARS + 50 });
  names.feed(Buffer.from(sse(chunk({ tool_calls: [{ index: 0, function: { name: 'n'.repeat(60) } }] })), 'utf8'));
  assert.equal(names.overflow, true, 'tool names are charged');
});

test('`hasError` says whether an in-band error frame came, beside or instead of a completion', () => {
  const clean = new ChatSseToJson();
  clean.feed(Buffer.from(sse(chunk({ content: 'fine' }, { finish_reason: 'stop' })), 'utf8'));
  clean.finish();
  assert.equal(clean.hasError, false);

  const partial = new ChatSseToJson();
  partial.feed(Buffer.from(sse(chunk({ content: 'par' })) + sse({ error: { message: 'cut', code: 502 } }), 'utf8'));
  const out = JSON.parse(partial.finish().toString('utf8'));
  assert.equal(partial.hasError, true);
  assert.equal(partial.failed, false, 'a partial answer with an error is still an answer');
  assert.equal(out.choices[0].message.content, 'par');
  assert.equal(out.error.message, 'cut');

  const only = new ChatSseToJson();
  only.feed(Buffer.from(sse({ error: { message: 'nope', code: 429 } }), 'utf8'));
  only.finish();
  assert.equal(only.hasError, true);
  assert.equal(only.failed, true);
});
