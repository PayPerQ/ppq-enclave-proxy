import test from 'node:test';
import assert from 'node:assert/strict';
import { CostExtractor } from '../src/cost.mjs';

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
