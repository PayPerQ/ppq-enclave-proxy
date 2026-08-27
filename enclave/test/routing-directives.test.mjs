import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyFreeModelStrip,
  applyToolStrip,
  applyAutoRouterConfig,
  parseAutoRouter,
} from '../src/routing.mjs';

// ── applyFreeModelStrip (issue #6, driven by hp is_free) ─────────────────────

test('free strip drops paid plugins', () => {
  const p = { model: 'ppq/free', plugins: [{ id: 'web' }], messages: [] };
  applyFreeModelStrip(p);
  assert.equal('plugins' in p, false);
});

test('free strip removes the web_search tool but keeps other tools', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false); // still has a tool → tool_choice untouched-absent
});

test('free strip deletes an emptied tools array + its tool_choice', () => {
  const p = {
    model: 'ppq/free',
    tools: [{ type: 'openrouter:web_search' }],
    tool_choice: 'auto',
  };
  applyFreeModelStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

// The gap this pair closes: web_search named ALONGSIDE other tools. The tools
// array stays non-empty, so the old code left tool_choice pointing at a tool it
// had just deleted and the upstream rejected the request outright — strictly
// worse than losing web search. hp deletes it here (chatPayload.ts), so leaving
// it was also a drift between the two paths.
test('free strip drops a tool_choice targeting the removed web_search tool', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { type: 'openrouter:web_search' },
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false);
});

test('free strip matches the function-name form of that tool_choice too', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { function: { name: 'openrouter:web_search' } },
  };
  applyFreeModelStrip(p);
  assert.equal('tool_choice' in p, false);
});

test('free strip keeps a tool_choice aimed at a surviving tool', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { type: 'function', function: { name: 'f' } },
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tool_choice, { type: 'function', function: { name: 'f' } });
});

// Guard the blast radius: with no web_search declared there is nothing to
// dangle, so tool_choice must survive untouched.
test('free strip leaves tool_choice alone when no web_search was present', () => {
  const p = {
    model: 'ppq/free',
    tools: [{ type: 'function', function: { name: 'f' } }],
    tool_choice: 'auto',
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal(p.tool_choice, 'auto');
});

test('free strip is a no-op when there is nothing to strip', () => {
  const p = { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] };
  applyFreeModelStrip(p);
  assert.deepEqual(p, { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] });
});

// ── applyToolStrip (issue #6, driven by hp strip_tools) ──────────────────────

test('tool strip removes tools + tool_choice for an unsupported model', () => {
  const p = {
    model: 'toyco/no-tools',
    tools: [{ type: 'function', function: { name: 'f' } }],
    tool_choice: 'auto',
  };
  applyToolStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

test('tool strip leaves an empty tools array alone (matches hp length>0 guard)', () => {
  const p = { model: 'toyco/no-tools', tools: [], tool_choice: 'auto' };
  applyToolStrip(p);
  assert.deepEqual(p.tools, []);
  assert.equal(p.tool_choice, 'auto');
});

test('tool strip is a no-op when there are no tools', () => {
  const p = { model: 'toyco/no-tools', messages: [] };
  applyToolStrip(p);
  assert.deepEqual(p, { model: 'toyco/no-tools', messages: [] });
});


// ── applyAutoRouterConfig (horse-power#790, driven by hp auto_router) ─────────

const SETTINGS = {
  allowed_models: ['openai/gpt-5.5', 'deepseek/deepseek-v4-flash'],
  cost_tier: 'low',
};

test('auto-router injects the allow-list plugin on openrouter/auto', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins, [
    {
      id: 'auto-router',
      allowed_models: ['openai/gpt-5.5', 'deepseek/deepseek-v4-flash'],
      cost_tier: 'low',
    },
  ]);
});

test('auto-router appends after existing plugins, preserving order', () => {
  const p = { model: 'openrouter/auto', plugins: [{ id: 'web' }], messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins.map((x) => x.id), ['web', 'auto-router']);
});

test('a caller-supplied auto-router plugin wins', () => {
  const caller = { id: 'auto-router', allowed_models: ['x/y'] };
  const p = { model: 'openrouter/auto', plugins: [caller], messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins, [caller]);
});

test('auto-router copies the allow-list rather than aliasing hp settings', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  p.plugins[0].allowed_models.push('mutated');
  assert.deepEqual(SETTINGS.allowed_models, [
    'openai/gpt-5.5',
    'deepseek/deepseek-v4-flash',
  ]);
});

// The DIRECTIVE decides, not the model string: hp omits `auto_router` for every
// model that should not be constrained (including suffixed Auto, which its
// normal path also leaves alone), so this applies whatever it is handed. Pinned
// because re-adding a model test here would silently diverge from hp's gate.
test('auto-router applies on whatever model hp sent the directive for', () => {
  const p = { model: 'openrouter/auto:exacto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins.map((x) => x.id), ['auto-router']);
});

// Without the directive the enclave must NOT invent an allow-list: an older hp
// that doesn't send `auto_router` has to keep working, and a fabricated list
// would be worse than none.
test('auto-router is a no-op when hp sent no directive', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, undefined);
  assert.equal('plugins' in p, false);
});


// ── parseAutoRouter (horse-power#790) ────────────────────────────────────────
//
// Guards against hp DRIFT, not against a hostile hp: a renamed field or retired
// cost format must degrade to "no allow-list" rather than become a plugin
// OpenRouter 400s on. Every reject below is a config change that would
// otherwise have turned into an outage.

const GOOD = { allowed_models: ['openai/gpt-5.5', 'anthropic/*'], cost_tier: 'low' };

test('parseAutoRouter accepts a well-formed directive', () => {
  assert.deepEqual(parseAutoRouter(GOOD), {
    allowed_models: ['openai/gpt-5.5', 'anthropic/*'],
    cost_tier: 'low',
  });
});

test('parseAutoRouter copies the array rather than aliasing hp state', () => {
  const out = parseAutoRouter(GOOD);
  out.allowed_models.push('mutated');
  assert.deepEqual(GOOD.allowed_models, ['openai/gpt-5.5', 'anthropic/*']);
});

test('parseAutoRouter rejects a retired numeric cost format', () => {
  // The exact drift this nearly shipped: hp moved cost_quality_tradeoff -> cost_tier.
  assert.equal(parseAutoRouter({ allowed_models: ['a/b'], cost_quality_tradeoff: 7 }), null);
});

for (const [name, bad] of [
  ['absent', undefined],
  ['null', null],
  ['not an object', 'nope'],
  ['no allow-list', { cost_tier: 'low' }],
  ['empty allow-list', { allowed_models: [], cost_tier: 'low' }],
  ['non-string entry', { allowed_models: ['a/b', 42], cost_tier: 'low' }],
  ['malformed slug', { allowed_models: ['a/b', 'has space'], cost_tier: 'low' }],
  ['unknown cost tier', { allowed_models: ['a/b'], cost_tier: 'cheap' }],
  ['over the length cap', { allowed_models: Array(101).fill('a/b'), cost_tier: 'low' }],
]) {
  test(`parseAutoRouter rejects: ${name}`, () => {
    assert.equal(parseAutoRouter(bad), null);
  });
}
