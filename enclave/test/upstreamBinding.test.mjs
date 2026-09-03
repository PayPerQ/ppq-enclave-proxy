// Two failure directions, both expensive.
//
// Too permissive and the substitution this exists to stop goes through. Too
// strict and legitimate direct traffic is pushed onto OpenRouter, which costs
// the OR margin on every affected request -- not an outage, but real money.
// So the deny cases and the permit cases are pinned with equal care.

import assert from 'node:assert/strict';
import test from 'node:test';

import { BINDING_VIOLATION, FAMILY_BINDINGS, checkBinding } from '../src/upstreamBinding.mjs';

test('refuses the substitution this exists to stop', () => {
  // An expensive model served by a cheap provider is the realistic fraud.
  const r = checkBinding('anthropic/claude-sonnet-5', 'api.fireworks.ai');
  assert.equal(r.allowed, false);
  assert.equal(r.family, 'anthropic/');
  assert.ok(r.permitted.includes('api.anthropic.com'));
  assert.ok(r.permitted.includes('openrouter.ai'));
});

test('permits each family its canonical direct provider', () => {
  assert.equal(checkBinding('anthropic/claude-haiku-4.5', 'api.anthropic.com').allowed, true);
  assert.equal(checkBinding('google/gemini-3-flash', 'aiplatform.googleapis.com').allowed, true);
  // Both Bedrock regions are provisioned, so both are legitimate.
  assert.equal(checkBinding('openai/gpt-5.5', 'bedrock-mantle.us-east-1.api.aws').allowed, true);
  assert.equal(checkBinding('openai/gpt-5.5', 'bedrock-mantle.us-east-2.api.aws').allowed, true);
});

test('always permits OpenRouter', () => {
  // Terminal candidate for every model. If this were ever refused, the request
  // would have nowhere left to go and the binding would cause outages.
  for (const m of ['anthropic/claude-x', 'openai/gpt-x', 'google/gemini-x', 'moonshotai/kimi-x', 'x']) {
    assert.equal(checkBinding(m, 'openrouter.ai').allowed, true, m);
  }
});

test('leaves unmapped namespaces alone', () => {
  // Conservative direction: an absent rule permits what already worked. Kimi
  // and DeepSeek legitimately go to Fireworks.
  assert.equal(checkBinding('moonshotai/kimi-k3', 'api.fireworks.ai').allowed, true);
  assert.equal(checkBinding('deepseek/deepseek-v4', 'api.fireworks.ai').allowed, true);
});

test('cross-family substitutions among mapped namespaces are refused', () => {
  assert.equal(checkBinding('openai/gpt-5.5', 'api.anthropic.com').allowed, false);
  assert.equal(checkBinding('anthropic/claude-x', 'aiplatform.googleapis.com').allowed, false);
  assert.equal(checkBinding('google/gemini-x', 'bedrock-mantle.us-east-1.api.aws').allowed, false);
});

test('matches the namespace case-insensitively', () => {
  assert.equal(checkBinding('Anthropic/Claude-Sonnet-5', 'api.fireworks.ai').allowed, false);
});

test('judges the REQUESTED model, not a wire id', () => {
  // The wire id for a direct Anthropic call is `claude-haiku-4-5` with no
  // namespace. Binding on that would silently match no rule and permit
  // everything, which is the quiet way this check becomes decorative.
  assert.equal(checkBinding('claude-haiku-4-5', 'api.fireworks.ai').allowed, true);
  assert.equal(checkBinding('anthropic/claude-haiku-4.5', 'api.fireworks.ai').allowed, false);
});

test('permits rather than throws on absent input', () => {
  // A binding check must never be why a request fails.
  assert.equal(checkBinding('anthropic/x', undefined).allowed, true);
  assert.equal(checkBinding('anthropic/x', '').allowed, true);
  assert.equal(checkBinding(undefined, 'api.fireworks.ai').allowed, true);
  assert.equal(checkBinding(null, null).allowed, true);
});

test('every mapped host is one the enclave can actually reach', () => {
  // A rule naming a host with no tunnel would be dead: the builder skips it for
  // want of a port before this check ever runs, so the rule would look like
  // protection while protecting nothing.
  const reachable = new Set([
    'openrouter.ai',
    'api.fireworks.ai',
    'bedrock-mantle.us-east-2.api.aws',
    'bedrock-mantle.us-east-1.api.aws',
    'api.anthropic.com',
    'aiplatform.googleapis.com',
  ]);
  for (const hosts of Object.values(FAMILY_BINDINGS)) {
    for (const h of hosts) assert.ok(reachable.has(h), `${h} is not reachable from the enclave`);
  }
});

test('the map is frozen', () => {
  // Measured into PCR0. Mutating it at runtime would mean the published source
  // no longer describes the running policy, which is the whole claim.
  assert.throws(() => {
    FAMILY_BINDINGS['anthropic/'] = ['api.fireworks.ai'];
  });
});

test('the violation reason is stable', () => {
  // Emitted in receipts and error reports; changing it breaks consumers.
  assert.equal(BINDING_VIOLATION, 'upstream_not_bound_to_family');
});
