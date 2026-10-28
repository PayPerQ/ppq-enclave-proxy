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

test('directResponseRewriter hides every declared echo alias behind the public slug (hp #1157)', () => {
  // Azure's grok-4-20-reasoning deployment answers `grok-4.20-beta-0309-reasoning`,
  // not its own id; hp declares the alias on the candidate.
  const r = directResponseRewriter('grok-4-20-reasoning', 'x-ai/grok-4.20', ['grok-4.20-beta-0309-reasoning']);
  const inp = 'data: {"id":"1","model":"grok-4.20-beta-0309-reasoning","choices":[]}\n';
  assert.equal(run(r, [inp]), 'data: {"id":"1","model":"x-ai/grok-4.20","choices":[]}\n');
  // The wire id itself still rewrites, and an alias split across chunks is handled.
  assert.equal(run(r, ['{"model":"grok-4-20-reasoning"}']), '{"model":"x-ai/grok-4.20"}');
  assert.equal(run(r, ['{"model":"grok-4.20-beta', '-0309-reasoning"}']), '{"model":"x-ai/grok-4.20"}');
});

test('directResponseRewriter rewrites the longest needle first, so a containing alias is replaced whole (hp #1157)', () => {
  const r = directResponseRewriter('dep', 'pub/slug', ['dep-beta', 'dep-beta-long']);
  assert.equal(run(r, ['"dep-beta-long" "dep-beta" "dep"']), '"pub/slug" "pub/slug" "pub/slug"');
  // Undeclared or malformed aliases are ignored, as is an alias equal to the slug.
  assert.equal(run(directResponseRewriter('a', 'b', ['', 7, 'b']), ['a b']), 'b b');
  assert.equal(run(directResponseRewriter('a', 'b'), ['a']), 'b');
  // A replacement is never re-matched, so a wire id contained in its own
  // public slug (every Grok row: `grok-4.7` → `x-ai/grok-4.7`) rewrites once.
  assert.equal(run(directResponseRewriter('grok-4.7', 'x-ai/grok-4.7'), ['{"model":"grok-4.7"}']), '{"model":"x-ai/grok-4.7"}');
  assert.equal(run(directResponseRewriter('m', 'public/m', ['m-beta']), ['"m-beta" "m"']), '"public/m" "public/m"');
  // Regex metacharacters in a needle are literal.
  assert.equal(run(new StreamReplacer([['a.b(c)', 'X']]), ['a.b(c) aXb(c)']), 'X aXb(c)');
});
