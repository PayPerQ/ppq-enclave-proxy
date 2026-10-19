// Two failure directions, both expensive.
//
// Too permissive and the substitution this exists to stop goes through. Too
// strict and legitimate direct traffic is pushed onto OpenRouter, which costs
// the OR margin on every affected request -- not an outage, but real money.
// So the deny cases and the permit cases are pinned with equal care.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BINDING_VIOLATION,
  FAMILY_BINDINGS,
  PROVIDER_BINDINGS,
  PROVIDER_HOST_MISMATCH,
  PROVIDER_KEY_MISMATCH,
  PROVIDER_UNKNOWN,
  bindingModelId,
  checkBinding,
  checkBindings,
  checkProviderBinding,
} from '../src/upstreamBinding.mjs';
import { FOUNDRY_HOST } from '../src/upstreams.mjs';
import { TINFOIL_HOST, TINFOIL_PROVIDER } from '../src/tinfoil.mjs';

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
  // GPT-6 Astra's only mantle region (2026-09-10).
  assert.equal(checkBinding('openai/gpt-6-astra', 'bedrock-mantle.us-west-2.api.aws').allowed, true);
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

test('a leading ~ (OpenRouter alias prefix) does not switch the check off', () => {
  // Oct 17-19 security reports (Raju Arling Toni): `~anthropic/claude-x`
  // matched no family and fell through to the permissive default, so one
  // character turned the binding into decoration. trace.mjs accepts the form
  // and webSearchTransforms.mjs strips it; this file now does too.
  assert.equal(bindingModelId('~Anthropic/Claude-X'), 'anthropic/claude-x');
  assert.equal(checkBinding('~anthropic/claude-x', 'api.fireworks.ai').allowed, false);
  assert.equal(checkBinding('~anthropic/claude-x', 'api.anthropic.com').allowed, true);
  assert.equal(checkBinding('~openai/gpt-5.5', 'api.anthropic.com').allowed, false);
  // Only a LEADING tilde is an alias marker.
  assert.equal(bindingModelId('a~b/c'), 'a~b/c');
});

test('judges the client literal AND the resolved id, refusing if either refuses', () => {
  // Oct 17-19 security reports (roolzer, Bron Zeee): the server judged only
  // hp's resolved id, and hp writes that id in the same answer as the
  // candidate list, so an hp resolving `anthropic/x` to `vendor/x` passed.
  const substituted = checkBindings(['anthropic/claude-sonnet-5', 'vendor/claude-sonnet-5'], 'api.fireworks.ai');
  assert.equal(substituted.allowed, false);
  assert.equal(substituted.model, 'anthropic/claude-sonnet-5', 'names the id that refused');
  assert.equal(substituted.family, 'anthropic/');
  // The other direction: an unmapped client string resolved into a mapped family.
  const resolvedIn = checkBindings(['claude-sonnet', 'anthropic/claude-sonnet-5'], 'api.fireworks.ai');
  assert.equal(resolvedIn.allowed, false);
  assert.equal(resolvedIn.model, 'anthropic/claude-sonnet-5');
  // Legitimate alias expansion passes: an unmapped literal permits everything,
  // and the resolved id reaches its own family's host.
  assert.equal(checkBindings(['claude-sonnet', 'anthropic/claude-sonnet-5'], 'api.anthropic.com').allowed, true);
  assert.equal(checkBindings(['anthropic/claude-sonnet-5', 'anthropic/claude-sonnet-5-20260101'], 'api.anthropic.com').allowed, true);
  // OpenRouter is permitted whatever the ids say; absent ids are ignored.
  assert.equal(checkBindings(['anthropic/x', 'vendor/x'], 'openrouter.ai').allowed, true);
  assert.equal(checkBindings([null, undefined, 'moonshotai/kimi-k3'], 'api.fireworks.ai').allowed, true);
  assert.equal(checkBindings([], 'api.fireworks.ai').allowed, true);
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
    'bedrock-mantle.us-west-2.api.aws', // boot.sh BEDROCK_USW2_VSOCK_PORT / run-host.sh 9453
    'api.anthropic.com',
    'aiplatform.googleapis.com',
    'inference.tinfoil.sh', // boot.sh TINFOIL_VSOCK_PORT / run-host.sh 9456 (#210)
    'api.venice.ai', // boot.sh VENICE_VSOCK_PORT / run-host.sh 9454
    'ppq-foundry.services.ai.azure.com', // boot.sh FOUNDRY_VSOCK_PORT / run-host.sh 9457
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

// ─── Provider binding: provider ↔ host ↔ key_ref (Oct 17-19 security reports) ──


test('refuses the misdirection the reports demonstrated: a foreign key to the Venice host', () => {
  // bgsparsiti finding 2: host api.venice.ai, key_ref openrouter, provider
  // fireworks -- the OpenRouter key would have gone to Venice and the settle
  // would have said Fireworks. Host disagrees with the provider first.
  const r = checkProviderBinding({ provider: 'fireworks', host: 'api.venice.ai', key_ref: 'openrouter' });
  assert.equal(r.allowed, false);
  assert.equal(r.reason, PROVIDER_HOST_MISMATCH);
  assert.equal(r.field, 'api.venice.ai');
  assert.deepEqual([...r.expected.hosts], ['api.fireworks.ai']);

  // bronzeee F2: the right provider name for the host, the wrong secret.
  const k = checkProviderBinding({ provider: 'venice', host: 'api.venice.ai', key_ref: 'fireworks' });
  assert.equal(k.allowed, false);
  assert.equal(k.reason, PROVIDER_KEY_MISMATCH);
  assert.equal(k.field, 'fireworks');
  assert.equal(k.expected.key_ref, 'venice');
});

test('every production pairing hp sends today is permitted', () => {
  // Too strict costs the OpenRouter margin on every affected request, so the
  // permit side is pinned as carefully as the deny side. These are the exact
  // shapes horse-power's registry / enclaveUpstreams emit.
  const live = [
    { provider: 'openrouter', host: 'openrouter.ai', key_ref: 'openrouter' },
    { provider: 'fireworks', host: 'api.fireworks.ai', key_ref: 'fireworks' },
    { provider: 'foundry', host: FOUNDRY_HOST, key_ref: 'foundry' },
    { provider: 'venice', host: 'api.venice.ai', key_ref: 'venice' },
    { provider: 'anthropic', host: 'api.anthropic.com', key_ref: 'anthropic' },
    { provider: 'bedrock', host: 'bedrock-mantle.us-east-1.api.aws', key_ref: 'bedrock' },
    { provider: 'bedrock', host: 'bedrock-mantle.us-east-2.api.aws', key_ref: 'bedrock' },
    { provider: 'bedrock', host: 'bedrock-mantle.us-west-2.api.aws', key_ref: 'bedrock' },
    { provider: 'vertex', host: 'aiplatform.googleapis.com', key_ref: 'vertex' },
    { provider: TINFOIL_PROVIDER, host: TINFOIL_HOST, key_ref: 'tinfoil' },
  ];
  for (const c of live) {
    assert.deepEqual(checkProviderBinding(c), { allowed: true }, JSON.stringify(c));
  }
});

test('a legacy candidate without a host is judged on its key_ref alone', () => {
  // Pre-host-keyed hp payloads: the builder picks the tunnel by provider
  // name, which cannot disagree with itself, so only the secret is checked.
  assert.deepEqual(checkProviderBinding({ provider: 'fireworks', key_ref: 'fireworks' }), { allowed: true });
  assert.equal(
    checkProviderBinding({ provider: 'fireworks', key_ref: 'openrouter' }).reason,
    PROVIDER_KEY_MISMATCH,
  );
  assert.equal(checkProviderBinding({ provider: 'fireworks', host: '', key_ref: 'fireworks' }).allowed, true);
});

test('a provider the enclave holds no secret for is refused, and so is a missing key_ref', () => {
  // Unlike the family map, this table is complete: every servable provider
  // has exactly one key and a closed set of tunnels, so an unlisted name has
  // no legitimate traffic to break and is refused rather than permitted.
  const u = checkProviderBinding({ provider: 'newprov', host: 'api.venice.ai', key_ref: 'venice' });
  assert.equal(u.allowed, false);
  assert.equal(u.reason, PROVIDER_UNKNOWN);
  assert.equal(checkProviderBinding({}).reason, PROVIDER_UNKNOWN);
  assert.equal(checkProviderBinding(null).reason, PROVIDER_UNKNOWN);
  assert.equal(checkProviderBinding(undefined).reason, PROVIDER_UNKNOWN);
  // No key_ref at all: `keys[undefined]` must never be what decides.
  assert.equal(checkProviderBinding({ provider: 'venice', host: 'api.venice.ai' }).reason, PROVIDER_KEY_MISMATCH);
});

test('provider bindings agree with the family bindings and name only reachable hosts', () => {
  // The two tables describe the same tunnels from two directions; a host in
  // one and not the other is a rule that protects nothing (or everything).
  const reachable = new Set([
    'openrouter.ai',
    'api.fireworks.ai',
    'bedrock-mantle.us-east-2.api.aws',
    'bedrock-mantle.us-east-1.api.aws',
    'bedrock-mantle.us-west-2.api.aws',
    'api.anthropic.com',
    'aiplatform.googleapis.com',
    TINFOIL_HOST,
    'api.venice.ai',
    FOUNDRY_HOST,
  ]);
  const bound = new Set();
  for (const rule of Object.values(PROVIDER_BINDINGS)) {
    for (const h of rule.hosts) {
      assert.ok(reachable.has(h), `${h} is not reachable from the enclave`);
      bound.add(h);
    }
  }
  for (const hosts of Object.values(FAMILY_BINDINGS)) {
    for (const h of hosts) assert.ok(bound.has(h), `${h} is in FAMILY_BINDINGS but no provider owns it`);
  }
  assert.ok(bound.has('openrouter.ai'));
});

test('the provider table is frozen and its reasons are stable', () => {
  // Measured into PCR0 (see FAMILY_BINDINGS); the reasons ride the trace and
  // the error report, so renaming one breaks hp's consumers.
  assert.throws(() => {
    PROVIDER_BINDINGS.venice = { hosts: ['api.fireworks.ai'], key_ref: 'venice' };
  });
  assert.throws(() => {
    PROVIDER_BINDINGS.venice.hosts.push('api.fireworks.ai');
  });
  assert.equal(PROVIDER_UNKNOWN, 'provider_unknown');
  assert.equal(PROVIDER_HOST_MISMATCH, 'provider_host_mismatch');
  assert.equal(PROVIDER_KEY_MISMATCH, 'provider_key_mismatch');
});
