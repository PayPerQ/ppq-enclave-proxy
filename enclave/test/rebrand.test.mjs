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

// ── ModelKeyRewriter: the model KEY, dated snapshots included (horse-power #1156) ──
import { ModelKeyRewriter } from '../src/rebrand.mjs';

const feedAll = (rw, chunks) => chunks.map((c) => rw.feed(Buffer.from(c)).toString()).join('') + rw.finish().toString();

test('ModelKeyRewriter rewrites the bare id and its dated snapshot, on every frame', () => {
  const rw = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  const frames =
    'data: {"type":"response.created","response":{"id":"r","model":"gpt-5.5-2026-04-23"}}\n\n' +
    'data: {"type":"response.output_text.delta","delta":"gpt-5.5 is fine"}\n\n' +
    'data: {"type":"response.completed","response":{"model":"gpt-5.5","usage":{"input_tokens":1}}}\n\n';
  const out = feedAll(rw, [frames]);
  assert.equal(out.match(/"model":"openai\/gpt-5\.5"/g).length, 2);
  assert.ok(!out.includes('2026-04-23'));
  // Model OUTPUT mentioning the id is untouched: quotes inside a string are escaped.
  assert.ok(out.includes('"delta":"gpt-5.5 is fine"'));
});

test('ModelKeyRewriter: a member split across chunks still rewrites; a non-streaming JSON body is handled', () => {
  const rw = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  const line = 'data: {"type":"response.created","response":{"model":"gpt-5.5-2026-04-23"}}\n\n';
  const cut = line.indexOf('gpt-5.5') + 3;
  assert.equal(feedAll(rw, [line.slice(0, cut), line.slice(cut)]), line.replace('gpt-5.5-2026-04-23', 'openai/gpt-5.5'));
  const json = JSON.stringify({ id: 'r', model: 'gpt-5.5-2026-04-23', output: [{ type: 'message', content: [{ type: 'output_text', text: 'x'.repeat(20_000) }] }] });
  const rw2 = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  const pieces = [];
  for (let i = 0; i < json.length; i += 3000) pieces.push(json.slice(i, i + 3000));
  const out = feedAll(rw2, pieces);
  assert.equal(JSON.parse(out).model, 'openai/gpt-5.5');
  assert.equal(out.length, json.length - 'gpt-5.5-2026-04-23'.length + 'openai/gpt-5.5'.length);
});

test('ModelKeyRewriter: another model, a -pro, or a different date shape is left alone; disabled when ids agree', () => {
  const rw = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  for (const other of ['gpt-5.5-pro', 'gpt-5.5-pro-2026-04-23', 'gpt-5.4-2026-03-05', 'openai/gpt-5.5', 'gpt-5.5-latest']) {
    const line = `data: {"model":"${other}"}\n\n`;
    assert.equal(feedAll(new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5'), [line]), line, other);
  }
  const same = new ModelKeyRewriter('openai/gpt-5.5', 'openai/gpt-5.5');
  assert.equal(same.enabled, false);
  // A regex-special character in the id is literal.
  assert.equal(feedAll(rw, ['data: {"model":"gpt-5x5"}\n\n']), 'data: {"model":"gpt-5x5"}\n\n');
});

test('ModelKeyRewriter never splits a surrogate pair at the force flush', () => {
  const rw = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  // A JSON body (no newline) long enough to force-flush, with an emoji placed
  // right at the cut (length - 512): the pair must stay whole on one side.
  const head = '{"model":"gpt-5.5-2026-04-23","instructions":"' + 'a'.repeat(8192 + 300 - 512 - 46);
  const json = head + '😀' + 'b'.repeat(511) + '"}';
  const out = Buffer.concat([rw.feed(Buffer.from(json)), rw.finish()]).toString('utf8');
  assert.ok(!out.includes('�'), 'no replacement characters');
  assert.equal(JSON.parse(out).instructions.includes('😀'), true);
  assert.equal(JSON.parse(out).model, 'openai/gpt-5.5');
});
