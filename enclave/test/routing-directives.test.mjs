import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyFreeModelStrip,
  applyToolStrip,
  applyAutoRouterConfig,
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
  cost_quality_tradeoff: 7,
};

test('auto-router injects the allow-list plugin on openrouter/auto', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins, [
    {
      id: 'auto-router',
      allowed_models: ['openai/gpt-5.5', 'deepseek/deepseek-v4-flash'],
      cost_quality_tradeoff: 7,
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

test('auto-router is a no-op on a normal model', () => {
  const p = { model: 'anthropic/claude-opus-5', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.equal('plugins' in p, false);
});

// Without the directive the enclave must NOT invent an allow-list: an older hp
// that doesn't send `auto_router` has to keep working, and a fabricated list
// would be worse than none.
test('auto-router is a no-op when hp sent no directive', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, undefined);
  assert.equal('plugins' in p, false);
});
