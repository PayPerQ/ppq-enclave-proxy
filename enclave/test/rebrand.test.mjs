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

test('directResponseRewriter hides a Foundry deployment echo behind the public slug', () => {
  // Fireworks on Foundry echoes the catalog model id (`FW-Kimi-K3`) in every
  // chunk regardless of the deployment name (probed 2026-10-08). hp names the
  // deployment after that id and sends it as upstream_model, so the literal
  // rewrite below is exactly what hides the Azure route from the client.
  const r = directResponseRewriter('FW-Kimi-K3', 'moonshotai/kimi-k3');
  const inp = 'data: {"id":"chatcmpl-1","model":"FW-Kimi-K3","choices":[{"index":0,"delta":{"reasoning_content":"We"}}]}\n';
  assert.equal(run(r, [inp]), 'data: {"id":"chatcmpl-1","model":"moonshotai/kimi-k3","choices":[{"index":0,"delta":{"reasoning_content":"We"}}]}\n');
});
