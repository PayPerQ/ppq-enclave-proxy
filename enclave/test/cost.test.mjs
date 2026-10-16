import test from 'node:test';
import assert from 'node:assert/strict';
import { CostExtractor, providerName } from '../src/cost.mjs';

const chunk = (obj) => Buffer.from(`data: ${JSON.stringify(obj)}\n\n`);

test('the served model is captured from the first streamed chunk, before any usage frame', () => {
  const x = new CostExtractor();
  x.feed(chunk({ id: 'gen-1', model: 'qwen/qwen3.8-max', choices: [{ delta: { content: 'hi' } }] }));
  const r = x.finish();
  assert.equal(r.model, 'qwen/qwen3.8-max');
  assert.equal(r.generationId, 'gen-1');
  assert.equal(r.outputTokens, 0);
});

test('the usage frame still wins over the early capture', () => {
  const x = new CostExtractor();
  x.feed(chunk({ id: 'gen-1', model: 'router/placeholder', choices: [{ delta: { content: 'a' } }] }));
  x.feed(chunk({ id: 'gen-1', model: 'qwen/qwen3.8-max', choices: [], usage: { prompt_tokens: 3, completion_tokens: 5, cost: 0.001 } }));
  const r = x.finish();
  assert.equal(r.model, 'qwen/qwen3.8-max');
  assert.equal(r.outputTokens, 5);
});

test('a "model" mention inside content is not taken as the served model', () => {
  const x = new CostExtractor();
  // No top-level model on this chunk; the content merely talks about one, with
  // a value the slug shape refuses (spaces, punctuation).
  x.feed(Buffer.from('data: {"id":"gen-1","choices":[{"delta":{"content":"the \\"model\\": \\"is a fine one, honestly\\""}}]}\n\n'));
  assert.equal(x.finish().model, undefined);
});

// ── the provider OpenRouter routed to ────────────────────────────────────

const usageChunk = (extra) =>
  chunk({ id: 'gen-1', model: 'openai/gpt-4o-mini', choices: [], usage: { prompt_tokens: 3, completion_tokens: 5, cost: 0.001 }, ...extra });

test('provider: captured from the usage chunk of a stream', () => {
  const x = new CostExtractor();
  x.feed(chunk({ id: 'gen-1', provider: 'OpenAI', choices: [{ delta: { content: 'hi' } }] }));
  x.feed(usageChunk({ provider: 'OpenAI' }));
  assert.equal(x.finish().provider, 'OpenAI');
});

test('provider: captured from a non-streamed JSON body', () => {
  const x = new CostExtractor();
  x.feed(Buffer.from(JSON.stringify({
    id: 'gen-1', model: 'google/gemini-3-flash', provider: 'Google AI Studio',
    choices: [{ message: { role: 'assistant', content: 'ok' } }],
    usage: { prompt_tokens: 3, completion_tokens: 1 },
  })));
  assert.equal(x.finish().provider, 'Google AI Studio');
});

test('provider: Responses and Anthropic shapes carry it inside the wrapped object or at the top', () => {
  const r = new CostExtractor();
  r.feed(chunk({ type: 'response.completed', response: { id: 'gen-2', model: 'm', provider: 'Azure', usage: { input_tokens: 2, output_tokens: 3 } } }));
  assert.equal(r.finish().provider, 'Azure');
  const r2 = new CostExtractor();
  r2.feed(chunk({ type: 'response.completed', provider: 'OpenAI', response: { id: 'gen-2', model: 'm', usage: { input_tokens: 2, output_tokens: 3 } } }));
  assert.equal(r2.finish().provider, 'OpenAI');
  const a = new CostExtractor();
  a.feed(chunk({ type: 'message_start', message: { id: 'gen-3', model: 'm', usage: { input_tokens: 0 }, provider: 'Google' } }));
  assert.equal(a.finish().provider, 'Google');
});

test('provider: absent when no usage-bearing frame names one', () => {
  const x = new CostExtractor();
  x.feed(chunk({ id: 'gen-1', provider: 'OpenAI', choices: [{ delta: { content: 'hi' } }] })); // not a usage frame
  x.feed(usageChunk({}));
  assert.equal(x.finish().provider, undefined);
  const y = new CostExtractor();
  y.feed(chunk({ id: 'gen-1', choices: [{ delta: { content: 'hi' } }] }));
  assert.equal(y.finish().provider, undefined);
});

test('provider: too long, a bad charset or a non-string is dropped', () => {
  for (const provider of [
    'x'.repeat(65),
    'Open<script>AI',
    'OpenAI\n',
    'Provider: "quoted"',
    'naïve',
    '',
    42,
    { name: 'OpenAI' },
    ['OpenAI'],
    null,
  ]) {
    const x = new CostExtractor();
    x.feed(usageChunk({ provider }));
    assert.equal(x.finish().provider, undefined, `accepted ${JSON.stringify(provider)}`);
  }
});

test('provider: the accepted shape — word chars, spaces and . ( ) / -, up to 64', () => {
  for (const ok of ['OpenAI', 'Amazon Bedrock', 'Google AI Studio', 'Together (lite)', 'Fireworks/Serverless', 'Novita.ai', 'x'.repeat(64), 'deep_infra-2']) {
    assert.equal(providerName(ok), ok);
  }
  const x = new CostExtractor();
  x.feed(usageChunk({ provider: 'Amazon Bedrock' }));
  assert.equal(x.finish().provider, 'Amazon Bedrock');
});

test('provider: capture does not disturb the billing numbers', () => {
  const x = new CostExtractor();
  x.feed(usageChunk({ provider: 'x'.repeat(200) }));
  const r = x.finish();
  assert.equal(r.provider, undefined);
  assert.equal(r.inputTokens, 3);
  assert.equal(r.outputTokens, 5);
  assert.equal(r.totalCost, 0.001);
});

// ── Fireworks on Foundry (Azure) ────────────────────────────────────────

test('a Foundry stream reports the catalog model, cached and reasoning tokens from its final usage frame', () => {
  // Captured 2026-10-08 from ppq-foundry.services.ai.azure.com /openai/v1 with
  // stream_options.include_usage: every chunk carries `usage: null` and the
  // catalog id as `model`; the last frame has empty choices and both the
  // completion_tokens_details and output_tokens_details spellings. No cost
  // field — hp prices the tokens.
  const x = new CostExtractor();
  x.feed(chunk({ id: 'chatcmpl-df03', object: 'chat.completion.chunk', model: 'FW-DeepSeek-V4-Pro', choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null, raw_output: null }], usage: null }));
  x.feed(chunk({ id: 'chatcmpl-df03', object: 'chat.completion.chunk', model: 'FW-DeepSeek-V4-Pro', choices: [{ index: 0, delta: { reasoning_content: 'We' }, finish_reason: null, raw_output: null }], usage: null }));
  x.feed(chunk({ id: 'chatcmpl-df03', object: 'chat.completion.chunk', model: 'FW-DeepSeek-V4-Pro', choices: [{ index: 0, delta: { content: '391' }, finish_reason: 'stop', raw_output: null }], usage: null }));
  x.feed(chunk({
    id: 'chatcmpl-df03', object: 'chat.completion.chunk', model: 'FW-DeepSeek-V4-Pro', choices: [],
    usage: {
      prompt_tokens: 2512, total_tokens: 2517, completion_tokens: 101,
      prompt_tokens_details: { cached_tokens: 2511 },
      completion_tokens_details: { reasoning_tokens: 98 },
      output_tokens_details: { reasoning_tokens: 98 },
    },
  }));
  x.feed(Buffer.from('data: [DONE]\n\n'));
  const r = x.finish();
  assert.equal(r.model, 'FW-DeepSeek-V4-Pro');
  // Only OpenRouter's `gen-` ids are kept as generation ids; Foundry's
  // `chatcmpl-` id is dropped exactly as Fireworks direct's is.
  assert.equal(r.generationId, undefined);
  assert.equal(r.inputTokens, 2512);
  assert.equal(r.outputTokens, 101);
  assert.equal(r.cacheReadTokens, 2511);
  assert.equal(r.reasoningTokens, 98);
  assert.equal(r.totalCost, 0);
  assert.equal(r.provider, undefined);
});
