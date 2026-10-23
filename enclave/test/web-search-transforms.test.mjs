import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  modelNamespace,
  webPluginBreaksModel,
  modelHasFastNativeSearch,
  WEB_PLUGIN_BROKEN_MODELS,
  FAST_NATIVE_SEARCH_NAMESPACES,
  hasWebSearch,
  webSearchToolActive,
  isActiveWebPlugin,
  isActivePlugin,
  applyWebSearchEngine,
  swapWebPluginForServerTool,
  swapWebSearchToolForPlugin,
} from '../src/webSearchTransforms.mjs';
import { transformPayload } from '../src/routing.mjs';

// ── modelNamespace (horse-power#827) ─────────────────────────────────────────

test('modelNamespace sees through the floating-alias ~ prefix', () => {
  assert.equal(modelNamespace('anthropic/claude-fable-5'), 'anthropic/');
  assert.equal(modelNamespace('~anthropic/claude-fable-latest'), 'anthropic/');
  assert.equal(modelNamespace('~Anthropic/Claude-Fable-Latest'), 'anthropic/');
  assert.equal(modelNamespace('perplexity/sonar-pro'), 'perplexity/');
});

test('modelNamespace returns empty for bare ids and non-strings', () => {
  assert.equal(modelNamespace('claude-sonnet-5'), '');
  assert.equal(modelNamespace(null), '');
  assert.equal(modelNamespace(undefined), '');
  assert.equal(modelNamespace(42), '');
});

// ── the allow-list (horse-power#676 / #827) ──────────────────────────────────

test('Sonnet 5 is recognised as plugin-broken (horse-power#827)', () => {
  assert.equal(WEB_PLUGIN_BROKEN_MODELS.includes('claude-sonnet-5'), true);
  assert.equal(webPluginBreaksModel('anthropic/claude-sonnet-5'), true);
});

test('the other directive-capable Claude models stay recognised (#676)', () => {
  for (const model of [
    'anthropic/claude-opus-5',
    'anthropic/claude-opus-4.8',
    'anthropic/claude-fable-5',
    'anthropic/claude-opus-5-fast',
  ]) {
    assert.equal(webPluginBreaksModel(model), true, `${model} must be plugin-broken`);
  }
});

test('floating-alias Claude ids are recognised too (horse-power#827)', () => {
  assert.equal(webPluginBreaksModel('~anthropic/claude-fable-latest'), true);
});

test('older Claude models and non-Anthropic models are not plugin-broken', () => {
  for (const model of [
    'anthropic/claude-sonnet-4.6',
    'anthropic/claude-haiku-4.5',
    'openai/gpt-5.6',
    'toyco/fable-thing', // fragment match must not escape the anthropic namespace
  ]) {
    assert.equal(webPluginBreaksModel(model), false, `${model} must NOT be plugin-broken`);
  }
});

// ── the disjointness invariant (horse-power#827) ─────────────────────────────

test('every plugin-broken namespace keeps the server tool (no ping-pong)', () => {
  // If this fails the two swaps can bounce a payload plugin -> tool -> plugin,
  // landing it back on the transport #676 exists to avoid.
  assert.equal(modelHasFastNativeSearch('anthropic/claude-sonnet-5'), true);
  assert.equal(modelHasFastNativeSearch('~anthropic/claude-fable-latest'), true);
  assert.equal(FAST_NATIVE_SEARCH_NAMESPACES.includes('anthropic/'), true);
});

test('routing does not ping-pong a plugin back onto broken models', () => {
  for (const model of [
    'anthropic/claude-sonnet-5',
    '~anthropic/claude-fable-latest',
    'anthropic/claude-opus-5',
  ]) {
    const p = { model, messages: [], plugins: [{ id: 'web' }] };
    transformPayload(p);
    assert.equal('plugins' in p, false, `${model} must not keep the web plugin`);
    assert.equal(
      p.tools?.some((t) => t?.type === 'openrouter:web_search'),
      true,
      `${model} must carry the server tool`,
    );
  }
});

// ── isOnline parity with horse-power (#8) ────────────────────────────────────
// The settle flag used to test `plugins` alone, so Auto mode — the DEFAULT for
// a user who never touched the setting — reported every search as offline.

test('hasWebSearch: the web plugin counts (On mode)', () => {
  assert.equal(hasWebSearch({ plugins: [{ id: 'web' }] }), true);
  assert.equal(hasWebSearch({ plugins: [{ id: 'something-else' }] }), false);
  assert.equal(hasWebSearch({ plugins: [] }), false);
  assert.equal(hasWebSearch({}), false);
  assert.equal(hasWebSearch(null), false);
});

test('hasWebSearch: a callable web_search tool counts (Auto mode)', () => {
  // The regression #8 is about.
  assert.equal(hasWebSearch({ tools: [{ type: 'openrouter:web_search' }] }), true);
});

test('hasWebSearch: a declared-but-uncallable tool does NOT count', () => {
  const tools = [{ type: 'openrouter:web_search' }];
  assert.equal(hasWebSearch({ tools, tool_choice: 'none' }), false);
  assert.equal(
    hasWebSearch({ tools, tool_choice: { type: 'function', function: { name: 'other' } } }),
    false,
  );
  // A forced choice that DOES target web search still counts.
  assert.equal(hasWebSearch({ tools, tool_choice: { type: 'openrouter:web_search' } }), true);
  assert.equal(
    hasWebSearch({ tools, tool_choice: { function: { name: 'openrouter:web_search' } } }),
    true,
  );
  // 'auto' leaves it callable.
  assert.equal(hasWebSearch({ tools, tool_choice: 'auto' }), true);
});

test('webSearchToolActive requires the tool to be declared at all', () => {
  assert.equal(webSearchToolActive({ tools: [] }), false);
  assert.equal(webSearchToolActive({ tools: [{ type: 'function' }] }), false);
  assert.equal(webSearchToolActive({}), false);
});

// ── `enabled: false` turns the web plugin OFF (horse-power #1094) ─────────────
// OpenRouter's documented per-request switch. Three shapes, pinned the same
// way horse-power's chatPayload tests pin them: absent and `true` are ON,
// `false` is OFF everywhere a `web` entry is read.

test('isActiveWebPlugin: absent and true are on, false is off, other ids never are', () => {
  assert.equal(isActiveWebPlugin({ id: 'web' }), true);
  assert.equal(isActiveWebPlugin({ id: 'web', enabled: true }), true);
  assert.equal(isActiveWebPlugin({ id: 'web', enabled: false }), false);
  assert.equal(isActiveWebPlugin({ id: 'auto-router' }), false);
  assert.equal(isActiveWebPlugin(null), false);
});

test('hasWebSearch: a disabled web plugin is not a search (three shapes)', () => {
  assert.equal(hasWebSearch({ plugins: [{ id: 'web' }] }), true);
  assert.equal(hasWebSearch({ plugins: [{ id: 'web', enabled: true }] }), true);
  assert.equal(hasWebSearch({ plugins: [{ id: 'web', enabled: false }] }), false);
  // A callable server tool beside a disabled plugin still counts: the tool is on.
  assert.equal(
    hasWebSearch({ plugins: [{ id: 'web', enabled: false }], tools: [{ type: 'openrouter:web_search' }] }),
    true,
  );
});

test('applyWebSearchEngine leaves a disabled plugin without Exa defaults', () => {
  const p = { model: 'deepseek/deepseek-v4-flash', plugins: [{ id: 'web', enabled: false }] };
  applyWebSearchEngine(p);
  assert.deepEqual(p.plugins, [{ id: 'web', enabled: false }]);
  const on = { model: 'deepseek/deepseek-v4-flash', plugins: [{ id: 'web', enabled: true }] };
  applyWebSearchEngine(on);
  assert.deepEqual(on.plugins, [{ id: 'web', enabled: true, engine: 'exa', mode: 'fast' }]);
});

test('#676 swap ignores a disabled plugin: nothing is carried onto the server tool', () => {
  const p = { model: 'anthropic/claude-opus-5', plugins: [{ id: 'web', enabled: false }] };
  swapWebPluginForServerTool(p);
  assert.deepEqual(p.plugins, [{ id: 'web', enabled: false }], 'the entry is left as the caller sent it');
  assert.equal(p.tools, undefined, 'no search tool is added for a search that is off');
});

test('#2550 collapse drops a disabled web entry beside the one it adds', () => {
  const p = {
    model: 'deepseek/deepseek-v4-flash',
    tools: [{ type: 'openrouter:web_search', parameters: { max_results: 3 } }],
    plugins: [{ id: 'web', enabled: false }],
  };
  swapWebSearchToolForPlugin(p);
  assert.equal(p.tools, undefined);
  assert.deepEqual(p.plugins, [{ id: 'web', max_results: 3 }], 'one active plugin, the disabled sibling gone');
});

test('transformPayload: a disabled plugin is neither swapped (#676) nor routed as a search', () => {
  // Opus 5 is a plugin-broken model: an ACTIVE web plugin is carried onto the
  // server tool before routing reads it. A disabled one is left exactly as the
  // caller sent it, no tool appears, and routing sees a plain plugins array.
  const on = { model: 'anthropic/claude-opus-5', messages: [{ role: 'user', content: 'hi' }], plugins: [{ id: 'web' }] };
  transformPayload(on);
  assert.equal(on.plugins, undefined, 'the active plugin was swapped away');
  assert.ok(on.tools?.some((t) => t.type === 'openrouter:web_search'), 'onto the server tool');
  const off = { model: 'anthropic/claude-opus-5', messages: [{ role: 'user', content: 'hi' }], plugins: [{ id: 'web', enabled: false }] };
  transformPayload(off);
  assert.deepEqual(off.plugins, [{ id: 'web', enabled: false }], 'left as the caller sent it: no swap, no Exa defaults');
  assert.equal(off.tools, undefined);
  assert.deepEqual(off.provider, { ignore: ['amazon-bedrock'] });
});

// ── isActivePlugin + callable-only #2550 collapse (horse-power #1095 / #1096) ─

test('isActivePlugin: enabled:false is the only inert shape, for any id', () => {
  assert.equal(isActivePlugin({ id: 'web' }), true);
  assert.equal(isActivePlugin({ id: 'web', enabled: true }), true);
  assert.equal(isActivePlugin({ id: 'web', enabled: false }), false);
  assert.equal(isActivePlugin({ id: 'file-parser', enabled: false }), false);
  assert.equal(isActivePlugin({ id: 'file-parser' }), true);
  assert.equal(isActivePlugin(null), true, 'a malformed entry is not treated as disabled');
});

test('#2550 collapse: tool_choice none keeps the tool and adds no plugin (hp #1096)', () => {
  const p = {
    model: 'deepseek/deepseek-v4-flash',
    tools: [{ type: 'openrouter:web_search' }],
    tool_choice: 'none',
  };
  const before = JSON.stringify(p);
  swapWebSearchToolForPlugin(p);
  assert.equal(JSON.stringify(p), before, 'left byte-identical: the caller switched search off');
});

test('#2550 collapse: a forced choice naming another function keeps everything (hp #1096)', () => {
  const p = {
    model: 'deepseek/deepseek-v4-flash',
    tools: [
      { type: 'function', function: { name: 'lookup' } },
      { type: 'openrouter:web_search' },
    ],
    tool_choice: { type: 'function', function: { name: 'lookup' } },
  };
  const before = JSON.stringify(p);
  swapWebSearchToolForPlugin(p);
  assert.equal(JSON.stringify(p), before);
});

test('#2550 collapse still runs for auto / absent / required / forced web_search (hp #1096)', () => {
  for (const choice of [undefined, 'auto', 'required', { type: 'openrouter:web_search' }]) {
    const p = { model: 'deepseek/deepseek-v4-flash', tools: [{ type: 'openrouter:web_search' }] };
    if (choice !== undefined) p.tool_choice = choice;
    swapWebSearchToolForPlugin(p);
    assert.equal(p.tools, undefined, `tool collapsed under ${JSON.stringify(choice)}`);
    assert.deepEqual(p.plugins, [{ id: 'web' }]);
    assert.equal(p.tool_choice, undefined, 'no tools survive, so no tool_choice either');
  }
});

test('#2550 collapse: disabled web sibling + tool_choice none is left byte-identical (CodeRabbit on #348)', () => {
  const p = {
    model: 'deepseek/deepseek-v4-flash',
    tools: [{ type: 'openrouter:web_search', parameters: { max_results: 3 } }],
    plugins: [{ id: 'web', enabled: false }],
    tool_choice: 'none',
  };
  const before = JSON.stringify(p);
  swapWebSearchToolForPlugin(p);
  assert.equal(JSON.stringify(p), before, 'the disabled plugin is not replaced by an active Exa one');
});

test('transformPayload: a Claude request whose only plugin is disabled keeps the Bedrock pin (hp #1095)', () => {
  const msgs = [{ role: 'user', content: 'hi' }];
  const off = { model: 'anthropic/claude-sonnet-4.5', messages: msgs, plugins: [{ id: 'web', enabled: false }] };
  transformPayload(off);
  assert.deepEqual(off.provider, {
    order: ['amazon-bedrock'],
    ignore: ['amazon-bedrock/claude-on-aws'],
    allow_fallbacks: false,
  });
  assert.deepEqual(off.plugins, [{ id: 'web', enabled: false }], 'entry untouched');

  const offOther = { model: 'anthropic/claude-sonnet-4.5', messages: msgs, plugins: [{ id: 'file-parser', enabled: false }] };
  transformPayload(offOther);
  assert.deepEqual(offOther.provider.order, ['amazon-bedrock'], 'a disabled non-web plugin keeps the pin too');

  const on = { model: 'anthropic/claude-sonnet-4.5', messages: msgs, plugins: [{ id: 'web' }] };
  transformPayload(on);
  assert.deepEqual(on.provider, { ignore: ['amazon-bedrock'] }, 'an active plugin still leaves Bedrock');

  const mixed = {
    model: 'anthropic/claude-sonnet-4.5',
    messages: msgs,
    plugins: [{ id: 'web', enabled: false }, { id: 'file-parser' }],
  };
  transformPayload(mixed);
  assert.deepEqual(mixed.provider, { ignore: ['amazon-bedrock'] }, 'a disabled web beside an active plugin still ignores Bedrock');
});
