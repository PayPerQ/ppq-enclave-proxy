import { test } from 'node:test';
import assert from 'node:assert/strict';
import { candidateToRow, isOpenRouter, buildDirectRequest, normalizeCandidates } from '../src/upstreams.mjs';

const fwCandidate = {
  provider: 'fireworks',
  api_style: 'openai',
  host: 'api.fireworks.ai',
  path: '/inference/v1/chat/completions',
  key_ref: 'fireworks',
  upstream_model: 'accounts/fireworks/models/kimi-k3',
  or_slug: 'moonshotai/kimi-k3',
  supports_tools: true,
  tier: 'default',
};
const ports = { fireworks: 9445, openrouter: 9443 };
const keys = { fireworks: 'sk-fw-key', openrouter: 'sk-or-key' };
const basePayload = {
  model: 'moonshotai/kimi-k3',
  messages: [{ role: 'user', content: 'hi' }],
  stream: true,
  temperature: 0.5,
};

test('candidateToRow maps the snake_case projection to the row shape', () => {
  assert.deepEqual(candidateToRow(fwCandidate), {
    provider: 'fireworks',
    upstreamModelId: 'accounts/fireworks/models/kimi-k3',
    orSlug: 'moonshotai/kimi-k3',
    serviceTier: '',
    supportsTools: true,
    supportsImageInput: false,
    enabled: true,
    enabledOverride: null,
  });
});

test('isOpenRouter identifies the terminal fallback', () => {
  assert.equal(isOpenRouter({ provider: 'openrouter' }), true);
  assert.equal(isOpenRouter(fwCandidate), false);
});

test('buildDirectRequest builds the Fireworks request for an eligible payload', () => {
  const r = buildDirectRequest({ candidate: fwCandidate, basePayload, ports, keys });
  assert.equal(r.skip, undefined);
  assert.equal(r.provider, 'fireworks');
  assert.equal(r.orSlug, 'moonshotai/kimi-k3');
  assert.equal(r.upstreamModel, 'accounts/fireworks/models/kimi-k3');
  assert.equal(r.opts.host, '127.0.0.1'); // vsock tunnel mouth
  assert.equal(r.opts.port, 9445);
  assert.equal(r.opts.servername, 'api.fireworks.ai'); // real TLS name validated E2E
  assert.equal(r.opts.path, '/inference/v1/chat/completions');
  assert.equal(r.opts.headers.authorization, 'Bearer sk-fw-key');
  const body = JSON.parse(r.bodyStr);
  assert.equal(body.model, 'accounts/fireworks/models/kimi-k3'); // from the row, not the payload
  assert.equal(body.temperature, 0.5);
  assert.deepEqual(body.stream_options, { include_usage: true });
  assert.equal('provider' in body, false);
});

test('buildDirectRequest skips when no tunnel/key is provisioned (falls back)', () => {
  assert.equal(buildDirectRequest({ candidate: fwCandidate, basePayload, ports: {}, keys }).skip, 'no_tunnel_or_key');
  assert.equal(buildDirectRequest({ candidate: fwCandidate, basePayload, ports, keys: {} }).skip, 'no_tunnel_or_key');
});

test('buildDirectRequest skips (with reason) when the payload is ineligible', () => {
  // `transforms` here, not `reasoning` — the reasoning object is TRANSLATED
  // since the canonicalization build (see eligibility.test.mjs).
  const r = buildDirectRequest({
    candidate: fwCandidate,
    basePayload: { ...basePayload, transforms: ['middle-out'] },
    ports,
    keys,
  });
  assert.equal(r.skip, 'unsupported_field');
  assert.equal(r.offendingField, 'transforms');
});

test('buildDirectRequest skips a web-search request (forces OpenRouter)', () => {
  // Both encodings must skip the direct (Fireworks) candidate — Fireworks can't
  // run web search and would silently drop it.
  for (const ws of [{ plugins: [{ id: 'web' }] }, { tools: [{ type: 'openrouter:web_search' }] }]) {
    const r = buildDirectRequest({ candidate: fwCandidate, basePayload: { ...basePayload, ...ws }, ports, keys });
    assert.equal(r.skip, 'web_search_requires_openrouter');
  }
});

test('buildDirectRequest skips a tools request when the row lacks tool support', () => {
  const r = buildDirectRequest({
    candidate: { ...fwCandidate, supports_tools: false },
    basePayload: { ...basePayload, tools: [{ type: 'function', function: { name: 'f' } }] },
    ports,
    keys,
  });
  assert.equal(r.skip, 'tools_unsupported_by_model');
});

test('normalizeCandidates guarantees a terminal OpenRouter candidate', () => {
  const vertexOnly = [{ provider: 'vertex', api_style: 'openai', key_ref: 'vertex', host: 'aiplatform.googleapis.com' }];
  // A direct-only list (hp contract violation) gains the terminal — so a
  // skipped-everywhere request (e.g. vertex with no mintable token) still
  // falls to OpenRouter instead of 502ing.
  const fixed = normalizeCandidates(vertexOnly);
  assert.equal(fixed.length, 2);
  assert.equal(isOpenRouter(fixed[1]), true);
  // A compliant list is preserved by content (the normalization rebuilds the
  // array unconditionally so dedupe cannot be skipped; nothing depends on
  // reference identity — the loop just iterates).
  const compliant = [...vertexOnly, { provider: 'openrouter' }];
  assert.deepEqual(normalizeCandidates(compliant), compliant);
  // Duplicate OR entries collapse even when the list is ALREADY terminal —
  // the shape the removed fast-path used to wave through.
  const doubled = normalizeCandidates([{ provider: 'openrouter' }, { provider: 'openrouter' }]);
  assert.deepEqual(doubled, [{ provider: 'openrouter' }]);
  const midAndEnd = normalizeCandidates([...vertexOnly, { provider: 'openrouter' }, { provider: 'openrouter' }]);
  assert.equal(midAndEnd.filter(isOpenRouter).length, 1);
  assert.equal(midAndEnd.length, 2);
  // A MISPLACED OpenRouter moves to the end (terminal is what the loop
  // pipes-regardless-of-status; presence alone was a half-guard): direct
  // candidates keep their relative order.
  const orTagged = { provider: 'openrouter', provider_directive: { sort: 'price' } };
  const misplaced = normalizeCandidates([orTagged, ...vertexOnly]);
  assert.equal(misplaced.length, 2);
  assert.equal(misplaced[0].provider, 'vertex');
  assert.equal(misplaced[1], orTagged); // the ORIGINAL entry, moved — not a synthetic
  // Multiple OR entries collapse into one terminal (the last one wins).
  const multi = normalizeCandidates([{ provider: 'openrouter' }, ...vertexOnly, orTagged, ...vertexOnly]);
  assert.equal(multi.filter(isOpenRouter).length, 1);
  assert.equal(multi[multi.length - 1], orTagged);
  assert.equal(multi.filter((c) => c.provider === 'vertex').length, 2);
  // Absent/empty → the pure-OpenRouter singleton (pre-Phase-1b behavior).
  assert.deepEqual(normalizeCandidates(undefined), [{ provider: 'openrouter' }]);
  assert.deepEqual(normalizeCandidates([]), [{ provider: 'openrouter' }]);
});

test('a Venice candidate is built like any other bearer-key direct upstream, on its own tunnel and path', () => {
  // hp's candidate (services/enclaveUpstreams.ts + veniceSeed.ts): OpenAI dialect,
  // Venice's own path prefix, the bare Venice id upstream, key_ref 'venice'.
  const venice = {
    provider: 'venice',
    api_style: 'openai',
    host: 'api.venice.ai',
    path: '/api/v1/chat/completions',
    key_ref: 'venice',
    upstream_model: 'venice-uncensored-1-2',
    or_slug: 'venice/venice-uncensored-1-2',
    supports_tools: false,
    supports_image_input: false,
  };
  const basePayload = { model: 'venice/venice-uncensored-1-2', messages: [{ role: 'user', content: 'hi' }], stream: true };
  const r = buildDirectRequest({ candidate: venice, basePayload, ports: { 'api.venice.ai': 9454 }, keys: { venice: 'vk' } });
  assert.equal(r.skip, undefined, JSON.stringify(r));
  assert.equal(r.opts.port, 9454);
  assert.equal(r.opts.servername, 'api.venice.ai');
  assert.equal(r.opts.path, '/api/v1/chat/completions');
  assert.equal(r.opts.headers.authorization, 'Bearer vk');
  assert.equal(JSON.parse(r.bodyStr).model, 'venice-uncensored-1-2');
  // Without the tunnel or the key it is skipped, which is exactly the state
  // production was in before this provider was wired.
  assert.equal(buildDirectRequest({ candidate: venice, basePayload, ports: {}, keys: { venice: 'vk' } }).skip, 'no_tunnel_or_key');
  assert.equal(buildDirectRequest({ candidate: venice, basePayload, ports: { 'api.venice.ai': 9454 }, keys: {} }).skip, 'no_tunnel_or_key');
});

test('a Venice body refuses Venice\'s own system prompt, and a caller cannot re-enable it', () => {
  // Measured in production 2026-09-23, minutes after Venice was first keyed
  // here: the same prompt billed 19 input tokens through horse-power (which
  // has always sent this flag) and 1578 through the enclave, because Venice
  // prepends ~1560 tokens of its own prompt when the flag is absent. That is
  // both a behaviour change on models chosen for having no house prompt and a
  // ~38x overcharge on every request.
  const venice = {
    provider: 'venice',
    api_style: 'openai',
    host: 'api.venice.ai',
    path: '/api/v1/chat/completions',
    key_ref: 'venice',
    upstream_model: 'gemma-4-uncensored',
    or_slug: 'venice/gemma-4-uncensored',
  };
  const ports = { 'api.venice.ai': 9454 };
  const keys = { venice: 'vk' };
  const sent = (payload) =>
    JSON.parse(buildDirectRequest({ candidate: venice, basePayload: payload, ports, keys }).bodyStr);

  const plain = sent({ model: 'venice/gemma-4-uncensored', messages: [{ role: 'user', content: 'hi' }] });
  assert.deepEqual(plain.venice_parameters, { include_venice_system_prompt: false });

  // A caller cannot re-enable the house prompt: venice_parameters is not an
  // allowed field, so a body carrying one is refused as unsupported and never
  // reaches Venice at all. This assignment is the only writer.
  const forged = buildDirectRequest({
    candidate: venice,
    basePayload: {
      model: 'venice/gemma-4-uncensored',
      messages: [{ role: 'user', content: 'hi' }],
      venice_parameters: { include_venice_system_prompt: true },
    },
    ports,
    keys,
  });
  assert.equal(forged.skip, 'unsupported_field');
  assert.equal(forged.offendingField, 'venice_parameters');

  // Every other provider's body is untouched.
  const fw = buildDirectRequest({ candidate: fwCandidate, basePayload, ports: { fireworks: 9445 }, keys: { fireworks: 'k' } });
  assert.equal('venice_parameters' in JSON.parse(fw.bodyStr), false);
});
