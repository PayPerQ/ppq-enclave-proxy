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
  VENICE_HOSTED_ABLITERATION_MODELS,
  buildDirectRequest,
} from '../src/upstreams.mjs';
import { MODEL_BINDINGS, checkBinding, checkBindings, checkProviderBinding } from '../src/upstreamBinding.mjs';
import {
  DIRECT_ONLY_MODELS,
  classifyDirectOnlyRefusal,
  directOnlyRefusalReason,
  directOnlyFor,
  directOnlyNamespaceFor,
  directOnlyProviders,
  isDirectOnlyModel,
} from '../src/directOnly.mjs';
import { IMAGE_DIRECT_PROVIDERS, WEB_SEARCH_DIRECT_PROVIDERS, ZDR_DIRECT_PROVIDERS } from '../src/eligibility.mjs';
import { PassThrough } from 'node:stream';
import {
  FAILURE_KINDS,
  abliterationFailureKind,
  readFailureBody,
  shouldClassifyFailureBody,
} from '../src/directFailureBody.mjs';

const FLASH = 'abliterated-model-large-flash';
const V2 = 'abliterated-model-large-v2';
// All three are published under the lab's namespace. Venice also hosts two.
const M = `abliteration/${FLASH}`;
const M_V2 = `abliteration/${V2}`;
// The ids those two were FIRST published under: hp still accepts them as
// aliases, so a client may still send one.
const LEGACY = `venice/abliteration-${FLASH}`;
const LEGACY_V2 = `venice/abliteration-${V2}`;
// The one Venice never hosted: a single upstream.
const OWN = 'abliteration/abliterated-model';

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
  const v2 = candidate({ upstream_model: V2, or_slug: M_V2, supports_image_input: false });
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

test('without tools, an inert tool_choice is dropped and one that demands a call is refused', () => {
  const none = body({ tool_choice: 'auto', tools: [], parallel_tool_calls: true });
  assert.equal(none.tool_choice, undefined);
  assert.equal(none.tools, undefined);
  assert.equal(none.parallel_tool_calls, undefined);
  assert.equal(body({ tool_choice: 'none' }).tool_choice, undefined);
  const tool = { type: 'function', function: { name: 'f', parameters: { type: 'object' } } };
  // A choice that demands a call cannot be honoured without tools: refused,
  // never dropped into a prose answer.
  const refused = { skip: 'unmappable_field', offendingField: 'tool_choice' };
  assert.deepEqual(build({ tool_choice: 'required' }), refused);
  assert.deepEqual(build({ tool_choice: 'required', tools: [] }), refused);
  assert.deepEqual(build({ tool_choice: { type: 'function', function: { name: 'f' } } }), refused);
  assert.equal(body({ tool_choice: 'required', tools: [tool] }).tool_choice, 'required');
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

test('capability sets: images and web search yes; zero data retention no', () => {
  assert.equal(IMAGE_DIRECT_PROVIDERS.has('abliteration'), true);
  assert.equal(ZDR_DIRECT_PROVIDERS.has('abliteration'), false);
  assert.equal(WEB_SEARCH_DIRECT_PROVIDERS.has('abliteration'), true);
  assert.equal(build({ provider: { zdr: true } }).skip, 'zdr_requested');
});

test('web search is asked for in the provider\'s own form, never as a tool or a plugin', () => {
  const fn = { type: 'function', function: { name: 'get_time', parameters: { type: 'object', properties: {} } } };
  // No search asked for: the field is not sent, so a plain turn never searches.
  assert.equal(body({}).web_search_options, undefined);
  // The plugin, and the server tool under both of its names.
  for (const payload of [
    { plugins: [{ id: 'web', max_results: 5 }] },
    { tools: [{ type: 'web_search' }] },
    { tools: [{ type: 'openrouter:web_search' }] },
  ]) {
    const b = body(payload);
    assert.deepEqual(b.web_search_options, {}, JSON.stringify(payload));
    assert.equal(b.plugins, undefined);
    assert.equal(b.tools, undefined);
    assert.equal(b.tool_choice, undefined);
  }
  // A plugin the caller switched off asks for nothing.
  const off = body({ plugins: [{ id: 'web', enabled: false }] });
  assert.equal(off.web_search_options, undefined);
  assert.equal(off.plugins, undefined);
  // Function tools stay, beside the search (the provider takes both).
  const mixed = body({ tools: [fn, { type: 'web_search' }], tool_choice: 'auto' });
  assert.deepEqual(mixed.tools, [fn]);
  assert.equal(mixed.tool_choice, 'auto');
  assert.deepEqual(mixed.web_search_options, {});
  // A choice naming the search tool has nothing left to name: dropped.
  for (const choice of [{ type: 'web_search' }, { type: 'function', function: { name: 'openrouter:web_search' } }]) {
    const b = body({ tools: [fn, { type: 'web_search' }], tool_choice: choice });
    assert.equal(b.tool_choice, undefined, JSON.stringify(choice));
    assert.deepEqual(b.web_search_options, {});
  }
  // The caller's OWN function called web_search is a function, not a search.
  const own = { type: 'function', function: { name: 'web_search', parameters: { type: 'object', properties: {} } } };
  const ownBody = body({ tools: [own], tool_choice: { type: 'function', function: { name: 'web_search' } } });
  assert.deepEqual(ownBody.tools, [own]);
  assert.equal(ownBody.web_search_options, undefined);
  // The model's own rules still apply to a searching turn.
  assert.deepEqual(build({ plugins: [{ id: 'web' }], min_p: 0.1 }), { skip: 'unmappable_field', offendingField: 'min_p' });
  // Anthropic's dated tool carries limits this surface cannot express.
  assert.equal(build({ tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }] }).skip, 'web_search_requires_openrouter');
});

test('family bindings: the two models Venice hosts reach Abliteration AI or Venice, under either id', () => {
  for (const id of [M, M_V2, LEGACY, LEGACY_V2]) {
    assert.equal(checkBinding(id, 'api.abliteration.ai').allowed, true, id);
    assert.equal(checkBinding(id, 'api.venice.ai').allowed, true, id);
    assert.equal(checkBinding(id, 'api.fireworks.ai').allowed, false, id);
    assert.equal(checkBinding(`~${id.toUpperCase()}`, 'api.fireworks.ai').allowed, false, id);
  }
  // Every other venice/ id stays on Venice alone.
  assert.equal(checkBinding('venice/venice-uncensored-1-2', 'api.venice.ai').allowed, true);
  assert.equal(checkBinding('venice/venice-uncensored-1-2', 'api.abliteration.ai').allowed, false);
  assert.equal(checkBinding('venice/abliteration-something-else', 'api.abliteration.ai').allowed, false);
  assert.equal(checkBinding('venice/deepseek-v4-1-flash-uncensored', 'api.abliteration.ai').allowed, false);
  // Every other abliteration/ id stays on Abliteration AI alone.
  assert.equal(checkBinding(OWN, 'api.abliteration.ai').allowed, true);
  assert.equal(checkBinding(OWN, 'api.venice.ai').allowed, false);
  assert.equal(checkBinding('abliteration/something-new', 'api.venice.ai').allowed, false);
  assert.equal(checkBinding('~Abliteration/x', 'api.fireworks.ai').allowed, false);
  // Exact ids, not prefixes: an id that merely STARTS like a widened one
  // keeps its family's single host.
  for (const near of [`${LEGACY}-other`, `${LEGACY_V2}x`, 'venice/abliteration-abliterated-model-large-other', `${LEGACY}:nitro`]) {
    assert.equal(checkBinding(near, 'api.abliteration.ai').allowed, false, near);
    assert.equal(checkBinding(near, 'api.venice.ai').allowed, true, near);
  }
  for (const near of [`${M}-other`, `${M_V2}x`, 'abliteration/abliterated-model-large-other', `${M}:nitro`]) {
    assert.equal(checkBinding(near, 'api.venice.ai').allowed, false, near);
    assert.equal(checkBinding(near, 'api.abliteration.ai').allowed, true, near);
  }
  // The two tables that widen those ids name the same four, and nothing else.
  assert.deepEqual(Object.keys(MODEL_BINDINGS).sort(), [M, M_V2, LEGACY, LEGACY_V2].sort());
  assert.deepEqual(Object.keys(DIRECT_ONLY_MODELS).sort(), Object.keys(MODEL_BINDINGS).sort());
  // A stale client sends the old id and hp resolves it to the new one: both
  // are judged, and both permit either upstream.
  for (const host of ['api.abliteration.ai', 'api.venice.ai']) {
    assert.equal(checkBindings([LEGACY, M], host).allowed, true, host);
  }
  // hp cannot resolve the client's id away from the family.
  assert.equal(checkBindings([M, 'vendor/x'], 'api.fireworks.ai').allowed, false);
  assert.equal(checkBindings([OWN, 'vendor/x'], 'api.venice.ai').allowed, false);
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

test('direct-only: the two models Venice hosts have two upstreams in order under either id, every other id one', () => {
  for (const id of [M, M_V2, LEGACY, LEGACY_V2, `~${M}`, M.toUpperCase(), LEGACY.toUpperCase()]) {
    assert.equal(isDirectOnlyModel(id), true, id);
    assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor(id)), ['abliteration', 'venice'], id);
  }
  // hp cannot declare the list away, or add to it.
  assert.deepEqual(directOnlyProviders(directOnlyFor(M, { provider: 'fireworks' })), ['abliteration', 'venice']);
  // Other venice/ ids: Venice alone, as before.
  assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor('venice/venice-uncensored-1-2')), ['venice']);
  assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor('venice/abliteration-something-else')), ['venice']);
  // Other abliteration/ ids: Abliteration AI alone.
  assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor(OWN)), ['abliteration']);
  assert.deepEqual(directOnlyProviders(directOnlyFor(OWN, { provider: 'venice' })), ['abliteration']);
  // Exact ids, not prefixes.
  for (const near of [`${LEGACY}-other`, `${LEGACY_V2}x`, `${LEGACY}:nitro`]) {
    assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor(near)), ['venice'], near);
  }
  for (const near of [`${M}-other`, `${M_V2}x`, `${M}:nitro`]) {
    assert.deepEqual(directOnlyProviders(directOnlyNamespaceFor(near)), ['abliteration'], near);
  }
  // A tier hp declared has its one provider; nothing has none.
  assert.deepEqual(directOnlyProviders(directOnlyFor('some-twin', { provider: 'fireworks' })), ['fireworks']);
  assert.deepEqual(directOnlyProviders(undefined), []);
});

test('two upstreams, neither served: the most retryable answer wins, the first upstream breaks ties', () => {
  const both = (o) => classifyDirectOnlyRefusal({ model: M, providers: ['abliteration', 'venice'], skipped: [], failed: [], ...o });
  const f = (provider, status, kind) => ({ provider, status, ...(kind ? { kind } : {}) });
  const sk = (provider, reason, field) => ({ provider, reason, field });
  // One was down: retry, even though the other could never take the request.
  assert.equal(both({ skipped: [sk('abliteration', 'unmappable_field', 'min_p')], failed: [f('venice', 500)] }).status, 503);
  assert.equal(both({ failed: [f('abliteration', 500)], skipped: [sk('venice', 'unmappable_field', 'logit_bias')] }).status, 503);
  // Down beats busy beats our own bug.
  assert.equal(both({ failed: [f('abliteration', 429), f('venice', 500)] }).status, 503);
  assert.equal(both({ failed: [f('abliteration', 429), f('venice', 400)] }).status, 429);
  assert.equal(both({ failed: [f('abliteration', 400), f('venice', 404)] }).status, 502);
  // Both say the request is the problem: the source's sentence is the answer.
  const fields = both({ skipped: [sk('abliteration', 'unmappable_field', 'min_p'), sk('venice', 'unmappable_field', 'logit_bias')] });
  assert.equal(fields.status, 400);
  assert.match(fields.message, /"min_p"/);
  // hp offered only one of them (the other is switched off): its answer stands.
  assert.equal(both({ skipped: [sk('venice', 'zdr_requested')] }).status, 400);
  assert.equal(both({ failed: [f('venice', 429)] }).status, 429);
  // hp offered neither.
  assert.equal(both({}).status, 404);
  // A safety refusal is the answer whatever the other upstream did.
  const policy = both({ failed: [f('abliteration', 403, 'content_policy')], skipped: [sk('venice', 'content_refused_upstream')] });
  assert.equal(policy.status, 400);
  assert.match(policy.message, /safety policy/);
  assert.match(both({ failed: [f('abliteration', 403, 'content_policy'), f('venice', 500)] }).message, /safety policy/);
  // Two failures from the SAME provider (hp listed it twice): the safety
  // refusal answers, not the 5xx recorded ahead of it.
  const twice = both({ failed: [f('abliteration', 500), f('abliteration', 403, 'content_policy')] });
  assert.equal(twice.status, 400);
  assert.match(twice.message, /safety policy/);
  // A single `provider` still works as before.
  assert.equal(classifyDirectOnlyRefusal({ model: OWN, provider: 'abliteration', skipped: [], failed: [f('abliteration', 429)] }).status, 429);
});

test('refusals: the safety filter is a 400, a rejected key is not, and no upstream is named', () => {
  const classify = (o) => classifyDirectOnlyRefusal({ model: M, provider: 'abliteration', skipped: [], failed: [], ...o });
  const failed = (status, kind) => classify({ failed: [{ provider: 'abliteration', status, ...(kind ? { kind } : {}) }] });
  const policy = failed(403, 'content_policy');
  assert.equal(policy.status, 400);
  assert.equal(policy.type, 'invalid_request_error');
  assert.match(policy.message, /safety policy/);
  // A 403 the envelope did not mark as the safety filter is OUR problem (a
  // permission on the key): an outage, worth a retry, never a content refusal.
  assert.equal(failed(403).status, 503);
  // 401 is our key: an outage from the caller's side, worth a retry.
  assert.equal(failed(401).status, 503);
  assert.equal(failed(400, 'too_many_images').status, 400);
  assert.match(failed(422, 'unsupported_media').message, /could not read an image/);
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
  for (const r of [policy, images, field, failed(401), failed(429), failed(400, 'too_many_images'), failed(422, 'unsupported_media')]) {
    assert.doesNotMatch(r.message.replaceAll(M, ''), /abliteration|openrouter|venice/i, r.message);
  }
});

// ── the failed body: read for this provider only, reduced to a kind ─────────

const envelope = (code, type) => JSON.stringify({ error: { code, type, message: 'x', param: null } });

test('the safety filter is told apart from a permission 403 by the envelope', () => {
  assert.equal(abliterationFailureKind(403, envelope('policy_violation', 'policy_error')), 'content_policy');
  assert.equal(abliterationFailureKind(403, envelope('policy_violation', 'permission_error')), 'content_policy');
  assert.equal(abliterationFailureKind(403, envelope('blocked', 'moderation_error')), 'content_policy');
  // Ours: a credential or permission problem, an envelope that says nothing.
  assert.equal(abliterationFailureKind(403, envelope('admin_credential_permission_denied', 'permission_error')), undefined);
  assert.equal(abliterationFailureKind(403, '<html>blocked</html>'), undefined);
  assert.equal(abliterationFailureKind(403, undefined), undefined);
  assert.equal(abliterationFailureKind(403, '{"error":"policy_violation"}'), undefined);
  assert.equal(abliterationFailureKind(403, 'null'), undefined);
  // The code is only a content refusal on a 403.
  assert.equal(abliterationFailureKind(500, envelope('policy_violation', 'policy_error')), undefined);
});

test('a media error is the caller\'s image, and every kind is in the closed set', () => {
  assert.equal(abliterationFailureKind(400, envelope('media_count_exceeded', 'media_error')), 'too_many_images');
  assert.equal(abliterationFailureKind(422, envelope('media_decode_failed', 'media_error')), 'unsupported_media');
  assert.equal(abliterationFailureKind(403, envelope('media_policy_disallows_remote_url', 'media_error')), 'unsupported_media');
  assert.equal(abliterationFailureKind(400, envelope('unsupported_parameter', 'validation_error')), undefined);
  for (const k of ['content_policy', 'too_many_images', 'unsupported_media']) assert.ok(FAILURE_KINDS.includes(k));
});

test('only this provider\'s unexplained 4xx bodies are read', () => {
  assert.equal(shouldClassifyFailureBody('abliteration', 403), true);
  assert.equal(shouldClassifyFailureBody('abliteration', 400), true);
  assert.equal(shouldClassifyFailureBody('abliteration', 422), true);
  // The status already says what these are.
  assert.equal(shouldClassifyFailureBody('abliteration', 401), false);
  assert.equal(shouldClassifyFailureBody('abliteration', 429), false);
  assert.equal(shouldClassifyFailureBody('abliteration', 503), false);
  assert.equal(shouldClassifyFailureBody('abliteration', undefined), false);
  for (const p of ['venice', 'fireworks', 'openrouter', 'anthropic']) assert.equal(shouldClassifyFailureBody(p, 403), false);
});

test('readFailureBody: bounded in size and time, never rejects, releases the stream', async () => {
  const ok = new PassThrough();
  const read = readFailureBody(ok);
  ok.end(envelope('policy_violation', 'policy_error'));
  assert.equal(abliterationFailureKind(403, await read), 'content_policy');

  const big = new PassThrough();
  const over = readFailureBody(big, { maxBytes: 8 });
  big.write('0123456789abcdef');
  assert.equal(await over, undefined);
  assert.equal(big.destroyed, true);

  const slow = new PassThrough();
  const timed = readFailureBody(slow, { timeoutMs: 20 });
  slow.write('{');
  assert.equal(await timed, undefined);
  assert.equal(slow.destroyed, true);

  const broken = new PassThrough();
  const errored = readFailureBody(broken);
  broken.destroy(new Error('reset'));
  assert.equal(await errored, undefined);
});

// ── the Venice route to the same two models follows the same rules ─────────

const veniceCandidate = (o = {}) => ({
  provider: 'venice',
  api_style: 'openai',
  host: 'api.venice.ai',
  path: '/api/v1/chat/completions',
  key_ref: 'venice',
  upstream_model: `abliteration-${FLASH}`,
  or_slug: M,
  supports_tools: true,
  supports_image_input: true,
  max_images_per_message: 4,
  zdr: false,
  ...o,
});
const veniceBuild = (payload = {}, cand = veniceCandidate()) =>
  buildDirectRequest({
    candidate: cand,
    basePayload: { model: M, messages: [user('hi')], ...payload },
    ports: { 'api.venice.ai': 9454 },
    keys: { venice: 'venice-key' },
  });

test('Venice passes these two models on, so the model rules apply on its route too', () => {
  assert.deepEqual(VENICE_HOSTED_ABLITERATION_MODELS, {
    [`abliteration-${FLASH}`]: FLASH,
    [`abliteration-${V2}`]: V2,
  });
  const refused = (field) => ({ skip: 'unmappable_field', offendingField: field });
  // Fields the model rejects.
  assert.deepEqual(veniceBuild({ min_p: 0.05 }), refused('min_p'));
  assert.deepEqual(veniceBuild({ logit_bias: { 1: -1 } }), refused('logit_bias'));
  // Sampling ranges, judged on Abliteration AI's id for the model, not Venice's.
  const v2 = veniceCandidate({ upstream_model: `abliteration-${V2}`, or_slug: M_V2, supports_image_input: false, max_images_per_message: 0 });
  assert.deepEqual(veniceBuild({ temperature: 1.5 }, v2), refused('temperature'));
  assert.equal(veniceBuild({ temperature: 1 }, v2).skip, undefined);
  assert.equal(veniceBuild({ temperature: 1.5 }).skip, undefined);
  assert.deepEqual(veniceBuild({ top_p: 0 }), refused('top_p'));
  // A tool_choice that demands a call with no tools.
  assert.deepEqual(veniceBuild({ tool_choice: 'required' }), refused('tool_choice'));
  // The request-wide image cap: 3 + 3 passes Venice's per-message 4 and is
  // still more than the model takes.
  const turn = (n) => user([{ type: 'text', text: 'a' }, ...Array.from({ length: n }, () => image())]);
  assert.deepEqual(veniceBuild({ messages: [turn(3), turn(3)] }), { skip: 'too_many_images', offendingField: '4' });
  assert.equal(veniceBuild({ messages: [turn(2), turn(2)] }).skip, undefined);
});

test('the shapes the model rejects are fixed on the Venice route as well, beside the Venice shaping', () => {
  const b = JSON.parse(veniceBuild({ tool_choice: 'auto', max_tokens: 9, max_completion_tokens: 7, top_k: 40 }).bodyStr);
  assert.equal(b.model, `abliteration-${FLASH}`);
  assert.equal(b.tool_choice, undefined);
  assert.equal(b.max_tokens, undefined);
  assert.equal(b.max_completion_tokens, 7);
  assert.equal(b.top_k, 40);
  // Venice's own shaping is untouched.
  assert.deepEqual(b.venice_parameters, { include_venice_system_prompt: false });
  // A searching turn that falls back to Venice is asked in Venice's form.
  const searching = JSON.parse(veniceBuild({ plugins: [{ id: 'web' }] }).bodyStr);
  assert.equal(searching.venice_parameters.enable_web_search, 'on');
  assert.equal(searching.web_search_options, undefined);
});

test('every other Venice model is untouched by those rules', () => {
  const other = veniceCandidate({ upstream_model: 'venice-uncensored-1-2', or_slug: 'venice/venice-uncensored-1-2' });
  const build = (payload) =>
    buildDirectRequest({
      candidate: other,
      basePayload: { model: 'venice/venice-uncensored-1-2', messages: [user('hi')], ...payload },
      ports: { 'api.venice.ai': 9454 },
      keys: { venice: 'venice-key' },
    });
  const b = JSON.parse(build({ min_p: 0.05, temperature: 1.9, top_p: 0, tool_choice: 'auto', max_tokens: 9, max_completion_tokens: 7 }).bodyStr);
  assert.equal(b.min_p, 0.05);
  assert.equal(b.temperature, 1.9);
  assert.equal(b.top_p, 0);
  assert.equal(b.tool_choice, 'auto');
  assert.equal(b.max_tokens, 9);
  // A near-miss id is not one of the two.
  const near = veniceCandidate({ upstream_model: `abliteration-${FLASH}-x` });
  assert.equal(JSON.parse(veniceBuild({ min_p: 0.05 }, near).bodyStr).min_p, 0.05);
});

test('why a refusal was given, for the error report: a closed token, and the field name when one was named', () => {
  const f = (provider, status, kind) => ({ provider, status, ...(kind ? { kind } : {}) });
  const one = (o) => directOnlyRefusalReason({ provider: 'abliteration', skipped: [], failed: [], ...o });
  // A field the model does not take: the reason and the field.
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'unmappable_field', field: 'min_p' }] }), { reason: 'UNMAPPABLE_FIELD', field: 'min_p' });
  // A skip with no field, and one whose field is not shaped like a name.
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'zdr_requested' }] }), { reason: 'ZDR_REQUESTED' });
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'unmappable_field', field: '<script>alert(1)</script>' }] }), { reason: 'UNMAPPABLE_FIELD' });
  // A skip whose `field` slot holds a VALUE reports no field: an image limit, an upstream host.
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'too_many_images', field: '4' }] }), { reason: 'TOO_MANY_IMAGES' });
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'upstream_not_bound_to_family', field: 'api.abliteration.ai' }] }), { reason: 'UPSTREAM_NOT_BOUND_TO_FAMILY' });
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'some_future_skip', field: 'looks_like_a_name' }] }), { reason: 'SOME_FUTURE_SKIP' });
  assert.deepEqual(one({ skipped: [{ provider: 'abliteration', reason: 'non_text_content', field: 'image_media_type' }] }), { reason: 'NON_TEXT_CONTENT', field: 'image_media_type' });
  // A skip reason that is not a token reports as a skip, not as its text.
  assert.equal(one({ skipped: [{ provider: 'abliteration', reason: 'not a token!' }] }).reason, 'SKIPPED');
  // What the upstream answered.
  assert.equal(one({ failed: [f('abliteration', 403, 'content_policy')] }).reason, 'CONTENT_POLICY');
  assert.equal(one({ failed: [f('abliteration', 400, 'too_many_images')] }).reason, 'UPSTREAM_TOO_MANY_IMAGES');
  assert.equal(one({ failed: [f('abliteration', 422, 'unsupported_media')] }).reason, 'UPSTREAM_UNSUPPORTED_MEDIA');
  assert.equal(one({ failed: [f('abliteration', 429)] }).reason, 'UPSTREAM_RATE_LIMITED');
  assert.equal(one({ failed: [f('abliteration', 400)] }).reason, 'UPSTREAM_REJECTED_REQUEST');
  assert.equal(one({ failed: [f('abliteration', 401)] }).reason, 'UPSTREAM_REJECTED_KEY');
  assert.equal(one({ failed: [f('abliteration', 500)] }).reason, 'UPSTREAM_ERROR_STATUS');
  assert.equal(one({ failed: [f('abliteration', undefined)] }).reason, 'UPSTREAM_NO_ANSWER');
  assert.equal(one({}).reason, 'NOT_OFFERED');
  // Two upstreams: the reason is the one of the answer that was given.
  const input = {
    model: M, providers: ['abliteration', 'venice'],
    skipped: [{ provider: 'abliteration', reason: 'unmappable_field', field: 'min_p' }],
    failed: [f('venice', 500)],
  };
  assert.equal(classifyDirectOnlyRefusal(input).status, 503);
  assert.deepEqual(directOnlyRefusalReason(input), { reason: 'UPSTREAM_ERROR_STATUS' });
  // The refusal the caller is answered with carries none of it.
  assert.deepEqual(Object.keys(classifyDirectOnlyRefusal(input)).sort(), ['code', 'message', 'status', 'type']);
});
