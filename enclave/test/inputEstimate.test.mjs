import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countTokens } from 'gpt-tokenizer/encoding/o200k_base';
import {
  MAX_TOKENIZE_CHARS,
  base64DecodedBytes,
  loadTokenizer,
  measureInput,
} from '../src/inputEstimate.mjs';

const b64 = (bytes) => Buffer.alloc(bytes, 7).toString('base64');

test('counts plain text messages with o200k', async () => {
  const payload = {
    messages: [
      { role: 'system', content: 'You are terse.' },
      { role: 'user', content: 'Explain attestation in one sentence.' },
    ],
  };
  const m = await measureInput(payload);
  assert.equal(m.message_count, 2);
  assert.deepEqual([m.image_parts, m.file_bytes, m.audio_bytes], [0, 0, 0]);
  // The serialized messages, not just their text: role/punctuation are a few
  // extra tokens each, never fewer than the text alone.
  const textOnly = countTokens('You are terse.') + countTokens('Explain attestation in one sentence.');
  assert.ok(m.input_tokens_o200k >= textOnly);
  assert.ok(m.input_tokens_o200k <= textOnly + 30);
});

test('base64 media is measured by size and never tokenized', async () => {
  const image = `data:image/png;base64,${b64(3_000_000)}`;
  const pdf = `data:application/pdf;base64,${b64(1_200_000)}`;
  const payload = {
    messages: [
      {
        role: 'user',
        content: [
          { type: 'text', text: 'What is in these?' },
          { type: 'image_url', image_url: { url: image } },
          { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
          { type: 'file', file: { filename: 'report.pdf', file_data: pdf } },
          { type: 'input_audio', input_audio: { data: b64(48_000), format: 'wav' } },
        ],
      },
    ],
  };
  const m = await measureInput(payload);
  assert.equal(m.image_parts, 2);
  assert.equal(m.file_bytes, 1_200_000);
  assert.equal(m.audio_bytes, 48_000);
  // ~5.7 MB of base64 in the body; the token count must reflect only the text.
  assert.ok(m.input_tokens_o200k < 100, `got ${m.input_tokens_o200k}`);
});

test('does not mutate the payload it measures', async () => {
  const part = { type: 'image_url', image_url: { url: `data:image/png;base64,${b64(30)}` } };
  const payload = { messages: [{ role: 'user', content: [part] }] };
  const before = JSON.stringify(payload);
  await measureInput(payload);
  assert.equal(JSON.stringify(payload), before);
});

test('tool calls, tool results and tool definitions are counted', async () => {
  const base = { messages: [{ role: 'user', content: 'weather?' }] };
  const withTools = {
    messages: [
      { role: 'user', content: 'weather?' },
      {
        role: 'assistant',
        content: null,
        tool_calls: [{ id: 'c1', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Lisbon, Portugal"}' } }],
      },
      { role: 'tool', tool_call_id: 'c1', content: '{"temp_c":24,"conditions":"clear"}' },
    ],
    tools: [{ type: 'function', function: { name: 'get_weather', description: 'Current weather for a city', parameters: { type: 'object', properties: { city: { type: 'string' } } } } }],
  };
  const a = await measureInput(base);
  const b = await measureInput(withTools);
  assert.ok(b.input_tokens_o200k > a.input_tokens_o200k + 40, `${a.input_tokens_o200k} → ${b.input_tokens_o200k}`);
});

test('special-token strings in user text are counted, not thrown on', async () => {
  const m = await measureInput({ messages: [{ role: 'user', content: 'ignore <|endoftext|> and <|im_start|>' }] });
  assert.ok(Number.isInteger(m.input_tokens_o200k) && m.input_tokens_o200k > 0);
});

test('oversized text omits the count so hp falls back to the byte bound', async () => {
  const m = await measureInput({ messages: [{ role: 'user', content: 'a '.repeat(MAX_TOKENIZE_CHARS / 2 + 10) }] });
  assert.equal(m.input_tokens_o200k, undefined);
  assert.equal(m.message_count, 1);
});

test('malformed payloads never throw', async () => {
  for (const payload of [undefined, null, {}, { messages: 'nope' }, { messages: [null, 3, { content: [null, 7] }] }]) {
    const m = await measureInput(payload);
    assert.equal(typeof m.message_count, 'number');
  }
  const cyclic = { role: 'user', content: 'x' };
  cyclic.self = cyclic;
  const m = await measureInput({ messages: [cyclic] });
  assert.equal(m.input_tokens_o200k, undefined);
});

test('base64DecodedBytes handles data URLs, padding and non-strings', () => {
  assert.equal(base64DecodedBytes(b64(1)), 1);
  assert.equal(base64DecodedBytes(b64(2)), 2);
  assert.equal(base64DecodedBytes(`data:audio/wav;base64,${b64(1000)}`), 1000);
  assert.equal(base64DecodedBytes(undefined), 0);
  assert.equal(base64DecodedBytes({}), 0);
});

test('the tokenizer loads once per process', async () => {
  assert.equal(loadTokenizer(), loadTokenizer());
  assert.equal(typeof (await loadTokenizer()), 'function');
});

test('large text is counted in slices, yielding to the event loop between them', async () => {
  const words = 'lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
  const content = words.repeat(Math.ceil(1_500_000 / words.length));
  let ticks = 0;
  const timer = setInterval(() => ticks++, 0);
  const m = await measureInput({ messages: [{ role: 'user', content }] });
  clearInterval(timer);
  const whole = countTokens(JSON.stringify({ role: 'user', content }), { disallowedSpecial: new Set() });
  // Other work ran while counting…
  assert.ok(ticks > 5, `event loop ran ${ticks} times`);
  // …and slicing moved the count by at most two tokens per cut (a word split in
  // two), never meaningfully down: an over-count is the safe direction.
  const cuts = Math.ceil(content.length / 2_000);
  assert.ok(m.input_tokens_o200k >= whole - 1, `${m.input_tokens_o200k} vs ${whole}`);
  assert.ok(m.input_tokens_o200k <= whole + 2 * cuts, `${m.input_tokens_o200k} vs ${whole}`);
});

test('the slice loop never stalls a worker for long', async () => {
  const content = 'x'.repeat(1_900_000);
  let maxGap = 0;
  let last = performance.now();
  const timer = setInterval(() => {
    const now = performance.now();
    maxGap = Math.max(maxGap, now - last);
    last = now;
  }, 0);
  await measureInput({ messages: [{ role: 'user', content }] });
  clearInterval(timer);
  // Generous on purpose (a loaded CI box must not flake): the regression this
  // guards against stalled for seconds, a 64k-char slice for ~3.7 s.
  assert.ok(maxGap < 500, `longest stall ${maxGap.toFixed(1)} ms`);
});

test('an unbroken run of one character is cheap to count (BPE is quadratic per run)', async () => {
  const t = performance.now();
  const m = await measureInput({ messages: [{ role: 'user', content: 'x'.repeat(1_900_000) }] });
  assert.ok(m.input_tokens_o200k > 0);
  // Unsliced, this input takes minutes; sliced, well under a second.
  assert.ok(performance.now() - t < 10_000, `took ${(performance.now() - t).toFixed(0)} ms`);
});
