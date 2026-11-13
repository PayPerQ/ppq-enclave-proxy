import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyHardProviderPin, applyRelayProviderPolicy, platformExclusionsFor } from '../src/routing.mjs';

const PIN = { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice'] };

test('a hard pin replaces the caller provider object (hp #1060)', () => {
  const body = { model: 'google/gemini-4-argon', provider: { order: ['google-ai-studio'], allow_fallbacks: true } };
  assert.equal(applyHardProviderPin(body, PIN), true);
  assert.deepEqual(body.provider, PIN);
});

test('the caller zdr survives the pin', () => {
  const body = { model: 'google/gemini-4-argon', provider: { zdr: true, sort: 'price' } };
  applyHardProviderPin(body, PIN);
  assert.deepEqual(body.provider, { ...PIN, zdr: true });
});

test('a body with no provider gets the pin', () => {
  const body = { model: 'google/gemini-4-argon' };
  applyHardProviderPin(body, PIN);
  assert.deepEqual(body.provider, PIN);
});

test('soft or absent directives leave the body untouched', () => {
  for (const directive of [null, undefined, {}, [], 'x', { order: ['fireworks/fast', 'fireworks'], allow_fallbacks: true }, { only: [] }]) {
    const body = { model: 'm', provider: { zdr: true } };
    assert.equal(applyHardProviderPin(body, directive), false);
    assert.deepEqual(body.provider, { zdr: true });
  }
});

test('the directive (hp auth object) is never aliased or mutated', () => {
  const directive = structuredClone(PIN);
  const body = { model: 'm' };
  applyHardProviderPin(body, directive);
  body.provider.only.push('x');
  body.provider.ignore.push('y');
  assert.deepEqual(directive, PIN);
});

// ── applyRelayProviderPolicy (#453): the relayed dialects carry the platform
// exclusions and, for Claude, the Anthropic → Vertex order ──────────────────

test('relay policy: a Claude body with no provider gets the exclusions and the Claude order', () => {
  for (const model of ['anthropic/claude-opus-5.5', 'claude-opus-5-5']) {
    const body = { model };
    assert.equal(applyRelayProviderPolicy(body, model), true);
    assert.deepEqual(body.provider, { ignore: ['venice', 'amazon-bedrock'], order: ['anthropic', 'google-vertex'] }, model);
  }
});

test('relay policy: merged into a caller provider object; a caller order or pin is kept', () => {
  const zdr = { model: 'anthropic/claude-opus-5.5', provider: { zdr: true, ignore: ['venice'] } };
  applyRelayProviderPolicy(zdr, zdr.model);
  assert.deepEqual(zdr.provider, { zdr: true, ignore: ['venice', 'amazon-bedrock'], order: ['anthropic', 'google-vertex'] });
  const ordered = { model: 'anthropic/claude-opus-5.5', provider: { order: ['google-vertex'], allow_fallbacks: false } };
  applyRelayProviderPolicy(ordered, ordered.model);
  assert.deepEqual(ordered.provider, { order: ['google-vertex'], allow_fallbacks: false, ignore: ['venice', 'amazon-bedrock'] }, 'the caller order wins');
  const pinned = { model: 'anthropic/claude-opus-5.5', provider: { only: ['anthropic'] } };
  applyRelayProviderPolicy(pinned, pinned.model);
  assert.deepEqual(pinned.provider, { only: ['anthropic'], ignore: ['venice', 'amazon-bedrock'] }, 'a pin wins');
});

test('relay policy: a non-Claude body gets the exclusions only; the Venice-only model keeps Venice', () => {
  const gpt = { model: 'openai/gpt-6-astra' };
  applyRelayProviderPolicy(gpt, gpt.model);
  assert.deepEqual(gpt.provider, { ignore: ['venice', 'amazon-bedrock'] });
  const dolphin = { model: 'cognitivecomputations/dolphin-mistral-24b-venice-edition' };
  applyRelayProviderPolicy(dolphin, dolphin.model);
  assert.deepEqual(dolphin.provider, { ignore: ['amazon-bedrock'] });
  assert.deepEqual(platformExclusionsFor('cognitivecomputations/dolphin-mistral-24b-venice-edition'), ['amazon-bedrock']);
  assert.deepEqual(platformExclusionsFor('z-ai/glm-5.3'), ['venice', 'amazon-bedrock']);
});

test('relay policy: rides on top of a hard pin, never duplicates, idempotent', () => {
  const body = { model: 'google/gemini-4-argon', provider: { zdr: true } };
  applyHardProviderPin(body, { ...PIN, ignore: ['venice', 'amazon-bedrock'] });
  assert.equal(applyRelayProviderPolicy(body, body.model), false, 'already excluded and pinned: a no-op');
  assert.deepEqual(body.provider, { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice', 'amazon-bedrock'], zdr: true });
  const twice = { model: 'anthropic/claude-opus-5.5' };
  applyRelayProviderPolicy(twice, twice.model);
  const after = JSON.stringify(twice.provider);
  assert.equal(applyRelayProviderPolicy(twice, twice.model), false);
  assert.equal(JSON.stringify(twice.provider), after);
});

test('relay policy: a non-object provider is left for OpenRouter to reject', () => {
  for (const provider of ['anthropic', 7, ['anthropic']]) {
    const body = { model: 'anthropic/claude-opus-5.5', provider };
    assert.equal(applyRelayProviderPolicy(body, body.model), false);
    assert.deepEqual(body.provider, provider);
  }
  assert.equal(applyRelayProviderPolicy(null), false);
});
