// Abliteration AI direct (horse-power #1371): the candidate the enclave
// builds, what it refuses before the request leaves, the bindings that keep
// the namespace and the key on one host, and the refusals a caller reads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ABLITERATION_HOST,
  ABLITERATION_MAX_IMAGES_PER_REQUEST,
  ABLITERATION_SAMPLING_LIMITS,
  ABLITERATION_UNSUPPORTED_FIELDS,
  buildDirectRequest,
} from '../src/upstreams.mjs';
import { checkBinding, checkBindings, checkProviderBinding } from '../src/upstreamBinding.mjs';
import { classifyDirectOnlyRefusal, directOnlyFor, directOnlyNamespaceFor, isDirectOnlyModel } from '../src/directOnly.mjs';
import { IMAGE_DIRECT_PROVIDERS, WEB_SEARCH_DIRECT_PROVIDERS, ZDR_DIRECT_PROVIDERS } from '../src/eligibility.mjs';

const FLASH = 'abliterated-model-large-flash';
const V2 = 'abliterated-model-large-v2';
const M = `abliteration/${FLASH}`;

// hp's candidate (services/enclaveUpstreams.ts + abliterationSeed.ts).
const candidate = (o = {}) => ({
  provider: 'abliteration',
  api_style: 'openai',
  host: 'api.abliteration.ai',
  path: '/v1/chat/completions',
  key_ref: 'abliteration',
  upstream_model: FLASH,
  or_slug: M,
  supports_tools: true,
  supports_image_input: true,
  tier: 'default',
  zdr: false,
  ...o,
});
const ports = { 'api.abliteration.ai': 9462, openrouter: 9443 };
const keys = { abliteration: 'ak_test_key', openrouter: 'sk-or-key' };
const user = (content) => ({ role: 'user', content });
const PNG = 'data:image/png;base64,iVBORw0KGgo=';
const image = (url = PNG) => ({ type: 'image_url', image_url: { url } });
const build = (payload = {}, cand = candidate()) =>
  buildDirectRequest({ candidate: cand, basePayload: { model: M, messages: [user('hi')], ...payload }, ports, keys });
const body = (payload, cand) => JSON.parse(build(payload, cand).bodyStr);

test('an abliteration candidate is built like any other bearer-key direct upstream, on its own tunnel', () => {
  const spec = build({ stream: true, temperature: 0.2, top_k: 40, usage: { include: true } });
  assert.equal(spec.skip, undefined);
  assert.equal(spec.provider, 'abliteration');
  assert.equal(spec.opts.host, '127.0.0.1');
  assert.equal(spec.opts.port, 9462);
  assert.equal(spec.opts.servername, ABLITERATION_HOST);
  assert.equal(spec.opts.path, '/v1/chat/completions');
  assert.equal(spec.opts.headers.authorization, 'Bearer ak_test_key');
  assert.equal(spec.opts.headers['x-session-affinity'], undefined);
  const b = JSON.parse(spec.bodyStr);
  // The wire model is the candidate's, never the payload's.
  assert.equal(b.model, FLASH);
  assert.equal(b.top_k, 40);
  assert.equal(b.usage, undefined);
  assert.deepEqual(b.stream_options, { include_usage: true });
  // No Venice shaping leaks onto this provider.
  assert.equal(b.venice_parameters, undefined);
});

test('no tunnel or key: a clean skip, never a request', () => {
  assert.equal(buildDirectRequest({ candidate: candidate(), basePayload: { model: M, messages: [user('hi')] }, ports: {}, keys }).skip, 'no_tunnel_or_key');
  assert.equal(buildDirectRequest({ candidate: candidate(), basePayload: { model: M, messages: [user('hi')] }, ports, keys: {} }).skip, 'no_tunnel_or_key');
});

test('fields the provider rejects are refused by name, not stripped', () => {
  assert.deepEqual([...ABLITERATION_UNSUPPORTED_FIELDS].sort(), ['logit_bias', 'min_p']);
  assert.deepEqual(build({ min_p: 0.05 }), { skip: 'unmappable_field', offendingField: 'min_p' });
  assert.deepEqual(build({ logit_bias: { 1: -1 } }), { skip: 'unmappable_field', offendingField: 'logit_bias' });
});

test('a sampling value outside the model range is refused, naming the field', () => {
  const v2 = candidate({ upstream_model: V2, or_slug: `abliteration/${V2}`, supports_image_input: false });
  assert.deepEqual(build({ temperature: 1.5 }, v2), { skip: 'unmappable_field', offendingField: 'temperature' });
  assert.equal(build({ temperature: 1 }, v2).skip, undefined);
  assert.equal(build({ temperature: 1.5 }).skip, undefined);
  assert.deepEqual(build({ temperature: 2.1 }), { skip: 'unmappable_field', offendingField: 'temperature' });
  assert.deepEqual(build({ top_p: 0 }), { skip: 'unmappable_field', offendingField: 'top_p' });
  assert.deepEqual(build({ top_p: 0.001 }, v2), { skip: 'unmappable_field', offendingField: 'top_p' });
  assert.equal(build({ top_p: 0.01 }, v2).skip, undefined);
  assert.equal(build({ top_p: 0.001 }).skip, undefined);
  // Every seeded model has limits, and an unknown wire id is not judged.
  assert.deepEqual(Object.keys(ABLITERATION_SAMPLING_LIMITS).sort(), ['abliterated-model', FLASH, V2]);
  assert.equal(build({ temperature: 9 }, candidate({ upstream_model: '__proto__' })).skip, undefined);
});

test('one token limit is sent when the caller sent both', () => {
  const b = body({ max_tokens: 100, max_completion_tokens: 50 });
  assert.equal(b.max_completion_tokens, 50);
  assert.equal(b.max_tokens, undefined);
  assert.equal(body({ max_tokens: 100 }).max_tokens, 100);
});

test('tool_choice and an empty tools array are dropped when there are no tools', () => {
  const none = body({ tool_choice: 'auto', tools: [], parallel_tool_calls: true });
  assert.equal(none.tool_choice, undefined);
  assert.equal(none.tools, undefined);
  assert.equal(none.parallel_tool_calls, undefined);
  const tool = { type: 'function', function: { name: 'f', parameters: { type: 'object' } } };
  const kept = body({ tool_choice: 'auto', tools: [tool] });
  assert.equal(kept.tool_choice, 'auto');
  assert.equal(kept.tools.length, 1);
});

test('images are counted across the whole request, and the media types are narrowed', () => {
  assert.equal(ABLITERATION_MAX_IMAGES_PER_REQUEST, 4);
  const turn = (n) => user([{ type: 'text', text: 'a' }, ...Array.from({ length: n }, () => image())]);
  assert.equal(build({ messages: [turn(4)] }).skip, undefined);
  assert.equal(build({ messages: [turn(2), turn(2)] }).skip, undefined);
  assert.deepEqual(build({ messages: [turn(5)] }), { skip: 'too_many_images', offendingField: '4' });
  assert.deepEqual(build({ messages: [turn(3), turn(3)] }), { skip: 'too_many_images', offendingField: '4' });
  assert.deepEqual(build({ messages: [user([image('data:image/heic;base64,AAAA')])] }), {
    skip: 'non_text_content',
    offendingField: 'image_media_type',
  });
  // A text-only row refuses images at the shared gate.
  assert.equal(build({ messages: [turn(1)] }, candidate({ supports_image_input: false })).skip, 'non_text_content');
});

test('capability sets: images yes; zero data retention and web search no', () => {
  assert.equal(IMAGE_DIRECT_PROVIDERS.has('abliteration'), true);
  assert.equal(ZDR_DIRECT_PROVIDERS.has('abliteration'), false);
  assert.equal(WEB_SEARCH_DIRECT_PROVIDERS.has('abliteration'), false);
  assert.equal(build({ provider: { zdr: true } }).skip, 'zdr_requested');
  assert.equal(build({ plugins: [{ id: 'web' }] }).skip, 'web_search_requires_openrouter');
});

test('the abliteration/ family reaches api.abliteration.ai and nothing else direct', () => {
  assert.equal(checkBinding(M, 'api.abliteration.ai').allowed, true);
  assert.equal(checkBinding(M, 'api.venice.ai').allowed, false);
  assert.equal(checkBinding(M, 'api.fireworks.ai').allowed, false);
  assert.equal(checkBinding('~Abliteration/x', 'api.fireworks.ai').allowed, false);
  // The Venice-hosted copies are venice/ ids and stay on Venice.
  assert.equal(checkBinding('venice/abliteration-abliterated-model-large-v2', 'api.venice.ai').allowed, true);
  assert.equal(checkBinding('venice/abliteration-abliterated-model-large-v2', 'api.abliteration.ai').allowed, false);
  // hp cannot resolve the client's id away from the family.
  assert.equal(checkBindings([M, 'vendor/x'], 'api.fireworks.ai').allowed, false);
});

test('the provider is bound to its one host, key and dialect', () => {
  assert.deepEqual(checkProviderBinding(candidate()), { allowed: true });
  assert.equal(checkProviderBinding(candidate({ host: 'api.venice.ai' })).reason, 'provider_host_mismatch');
  assert.equal(checkProviderBinding(candidate({ key_ref: 'openrouter' })).reason, 'provider_key_mismatch');
  assert.equal(checkProviderBinding(candidate({ api_style: 'bedrock' })).reason, 'provider_api_style_mismatch');
  // Another provider's name cannot borrow this host or key.
  assert.equal(checkProviderBinding({ provider: 'venice', host: 'api.abliteration.ai', key_ref: 'venice' }).reason, 'provider_host_mismatch');
  assert.equal(checkProviderBinding({ provider: 'fireworks', host: 'api.fireworks.ai', key_ref: 'abliteration' }).reason, 'provider_key_mismatch');
});

test('abliteration/* is direct-only: no OpenRouter terminal', () => {
  assert.equal(isDirectOnlyModel(M), true);
  assert.deepEqual(directOnlyNamespaceFor('~Abliteration/x'), { prefix: 'abliteration/', provider: 'abliteration' });
  // hp cannot declare the namespace away.
  assert.deepEqual(directOnlyFor(M, { provider: 'fireworks' }), { prefix: 'abliteration/', provider: 'abliteration' });
  assert.equal(isDirectOnlyModel('venice/abliteration-abliterated-model-large-v2'), true);
  assert.equal(directOnlyNamespaceFor('venice/abliteration-abliterated-model-large-v2').provider, 'venice');
});

test('refusals: the safety filter is a 400, a rejected key is not, and no upstream is named', () => {
  const classify = (o) => classifyDirectOnlyRefusal({ model: M, provider: 'abliteration', skipped: [], failed: [], ...o });
  const failed = (status) => classify({ failed: [{ provider: 'abliteration', status }] });
  const policy = failed(403);
  assert.equal(policy.status, 400);
  assert.equal(policy.type, 'invalid_request_error');
  assert.match(policy.message, /safety policy/);
  // 401 is our key: an outage from the caller's side, worth a retry.
  assert.equal(failed(401).status, 503);
  assert.equal(failed(402).status, 503);
  assert.equal(failed(429).status, 429);
  assert.equal(failed(400).status, 502);
  // A 403 from any other direct-only provider keeps its meaning.
  const venice403 = classifyDirectOnlyRefusal({
    model: 'venice/x', provider: 'venice', skipped: [], failed: [{ provider: 'venice', status: 403 }],
  });
  assert.equal(venice403.status, 503);
  const images = classify({ skipped: [{ provider: 'abliteration', reason: 'too_many_images', field: '4' }], supportsImages: true });
  assert.equal(images.status, 400);
  assert.match(images.message, /at most 4 images per request/);
  const field = classify({ skipped: [{ provider: 'abliteration', reason: 'unmappable_field', field: 'min_p' }] });
  assert.match(field.message, /"min_p"/);
  for (const r of [policy, images, field, failed(401), failed(429)]) {
    assert.doesNotMatch(r.message.replaceAll(M, ''), /abliteration|openrouter|venice/i, r.message);
  }
});
