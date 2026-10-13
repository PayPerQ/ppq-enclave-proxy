import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyHardProviderPin } from '../src/routing.mjs';

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
