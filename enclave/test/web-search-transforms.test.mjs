import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  modelNamespace,
  webPluginBreaksModel,
  modelHasFastNativeSearch,
  WEB_PLUGIN_BROKEN_MODELS,
  FAST_NATIVE_SEARCH_NAMESPACES,
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
