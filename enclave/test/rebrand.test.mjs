import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Rebrander, StreamReplacer, directResponseRewriter } from '../src/rebrand.mjs';

const run = (r, chunks) => {
  let out = '';
  for (const c of chunks) out += r.feed(Buffer.from(c, 'utf8')).toString('utf8');
  out += r.finish().toString('utf8');
  return out;
};

test('Rebrander replaces OPENROUTER → PPQ.AI', () => {
  assert.equal(run(new Rebrander(), [': OPENROUTER PROCESSING\n']), ': PPQ.AI PROCESSING\n');
});

test('Rebrander rewrites a token split across a chunk boundary', () => {
  assert.equal(run(new Rebrander(), [': OPEN', 'ROUTER PROCESSING']), ': PPQ.AI PROCESSING');
});

test('Rebrander leaves mixed-case "OpenRouter" untouched', () => {
  assert.equal(run(new Rebrander(), ['I use OpenRouter daily']), 'I use OpenRouter daily');
});

test('directResponseRewriter rewrites the wire model id → or_slug', () => {
  const r = directResponseRewriter('accounts/fireworks/models/kimi-k3', 'moonshotai/kimi-k3');
  const inp = 'data: {"model":"accounts/fireworks/models/kimi-k3","choices":[]}\n';
  assert.equal(run(r, [inp]), 'data: {"model":"moonshotai/kimi-k3","choices":[]}\n');
});

test('directResponseRewriter handles the model id split across chunks', () => {
  const r = directResponseRewriter('accounts/fireworks/models/kimi-k3', 'moonshotai/kimi-k3');
  assert.equal(
    run(r, ['{"model":"accounts/fireworks', '/models/kimi-k3"}']),
    '{"model":"moonshotai/kimi-k3"}',
  );
});

test('StreamReplacer no-op when needle absent', () => {
  assert.equal(run(new StreamReplacer([['x', 'y']]), ['hello world']), 'hello world');
});

test('directResponseRewriter maps a router\'s served id to the model\'s own slug, as a whole member only', () => {
  const served = { 'glm-5p3-flash': 'z-ai/glm-5.3-flash', 'claude-opus-5-5': 'anthropic/claude-opus-5.5' };
  const r = directResponseRewriter('firerouter/claude-opus-5-5/kimi-k3/glm-5p3-flash', 'firerouter/eco', served);
  const inp = 'data: {"id":"x","model":"glm-5p3-flash","choices":[{"delta":{"content":"glm-5p3-flash is fast"}}]}\n';
  assert.equal(
    run(r, [inp]),
    'data: {"id":"x","model":"z-ai/glm-5.3-flash","choices":[{"delta":{"content":"glm-5p3-flash is fast"}}]}\n',
  );
  assert.equal(run(r, ['{"model": "claude-opus-5-5"}']), '{"model": "anthropic/claude-opus-5.5"}');
  assert.equal(run(r, ['{"model":"accounts/fireworks/models/glm-5p3-flash"}']), '{"model":"z-ai/glm-5.3-flash"}');
  // The router id itself is still hidden behind the public slug.
  assert.equal(
    run(r, ['{"model":"firerouter/claude-opus-5-5/kimi-k3/glm-5p3-flash"}']),
    '{"model":"firerouter/eco"}',
  );
});

test('directResponseRewriter served-id rewrite survives a chunk boundary and ignores malformed maps', () => {
  const r = directResponseRewriter('u', 'firerouter/auto', { 'glm-5p3': 'z-ai/glm-5.3', bad: 7, same: 'same' });
  assert.equal(run(r, ['{"model":"glm-', '5p3"}']), '{"model":"z-ai/glm-5.3"}');
  assert.equal(run(r, ['{"model":"same"}']), '{"model":"same"}');
  assert.equal(run(directResponseRewriter('u', 'o', null), ['{"model":"glm-5p3"}']), '{"model":"glm-5p3"}');
});
