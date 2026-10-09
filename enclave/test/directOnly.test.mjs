import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyDirectOnlyRefusal,
  directOnlyNamespaceFor,
  isDirectOnlyModel,
  DIRECT_ONLY_NOT_FOUND_CODE,
  DIRECT_ONLY_RATE_LIMITED_CODE,
  DIRECT_ONLY_UNAVAILABLE_CODE,
  DIRECT_ONLY_UNSUPPORTED_CODE,
  DIRECT_ONLY_UPSTREAM_CODE,
} from '../src/directOnly.mjs';

const M = 'venice/venice-uncensored-1-2';
const classify = (o = {}) => classifyDirectOnlyRefusal({ model: M, provider: 'venice', skipped: [], failed: [], ...o });
const skip = (reason, field) => classify({ skipped: [{ provider: 'venice', reason, field }] });

test('which models are direct-only', () => {
  assert.equal(isDirectOnlyModel('venice/venice-uncensored-1-2'), true);
  assert.deepEqual(directOnlyNamespaceFor('venice/gemma-4-uncensored'), { prefix: 'venice/', provider: 'venice' });
  // The OpenRouter-served dolphin carries "venice" mid-id and has a twin.
  assert.equal(isDirectOnlyModel('cognitivecomputations/dolphin-mistral-24b-venice-edition'), false);
  assert.equal(isDirectOnlyModel('openai/gpt-4o-mini'), false);
  for (const v of [undefined, null, '', 7, {}]) assert.equal(isDirectOnlyModel(v), false);
});

test('a request the model cannot honour is a 400 that says what to change', () => {
  const images = skip('too_many_images', '1');
  assert.equal(images.status, 400);
  assert.equal(images.type, 'invalid_request_error');
  assert.equal(images.code, DIRECT_ONLY_UNSUPPORTED_CODE);
  assert.equal(images.message, `The model "${M}" accepts at most 1 image per message. Send fewer images in one message and retry.`);
  assert.match(skip('too_many_images', '10').message, /at most 10 images per message/);
  // A limit that did not survive the trip still produces a true sentence.
  assert.match(skip('too_many_images', undefined).message, /accepts fewer images per message/);

  assert.equal(
    skip('unmappable_field', 'logit_bias').message,
    `The request field "logit_bias" is not supported by the model "${M}". Remove it and retry.`,
  );
  assert.match(skip('tools_unsupported_by_model').message, /does not support tool calling/);
  assert.match(skip('web_search_requires_openrouter').message, /does not support web search/);
  assert.match(skip('response_format_unsupported').message, /"response_format"/);
});

test('non_text_content gives different advice on a row that takes images', () => {
  const vision = classify({ skipped: [{ provider: 'venice', reason: 'non_text_content', field: 'image_media_type' }], supportsImages: true });
  assert.match(vision.message, /PNG, JPEG or WebP images sent as base64 data URLs/);
  const textOnly = classify({ skipped: [{ provider: 'venice', reason: 'non_text_content' }], supportsImages: false });
  assert.match(textOnly.message, /accepts text-only messages/);
});

test('a field name is echoed only when it looks like one', () => {
  for (const hostile of ['<script>alert(1)</script>', 'a b', 'x'.repeat(200), 'line\nbreak', '']) {
    const r = skip('unsupported_field', hostile);
    assert.equal(r.status, 400);
    assert.equal(r.message, `The request contains a field the model "${M}" does not support. Remove it and retry.`);
  }
  assert.match(skip('unsupported_field', 'top_a').message, /The request field "top_a"/);
});

test('a reason this table does not know is still a refusal, never a fallback', () => {
  const r = skip('some_future_reason');
  assert.equal(r.status, 400);
  assert.equal(r.code, DIRECT_ONLY_UNSUPPORTED_CODE);
  assert.equal(r.message, `The model "${M}" cannot be served for this request.`);
});

test('not reachable from here right now is a 503, not the caller\'s fault', () => {
  for (const reason of ['no_tunnel_or_key', 'upstream_not_bound_to_family', 'model_disabled']) {
    const r = skip(reason);
    assert.equal(r.status, 503, reason);
    assert.equal(r.type, 'api_error');
    assert.equal(r.code, DIRECT_ONLY_UNAVAILABLE_CODE);
  }
});

test('hp offered no candidate for the provider: the id is not available here', () => {
  const r = classify({ skipped: [{ provider: 'fireworks', reason: 'no_tunnel_or_key' }] });
  assert.equal(r.status, 404);
  assert.equal(r.code, DIRECT_ONLY_NOT_FOUND_CODE);
  assert.equal(skip('model_not_in_catalog').status, 404);
});

test('an attempt that was made and failed is classified by its status', () => {
  const failed = (status) => classify({ failed: [{ provider: 'venice', status }] });
  assert.equal(failed(429).status, 429);
  assert.equal(failed(429).type, 'rate_limit_error');
  assert.equal(failed(429).code, DIRECT_ONLY_RATE_LIMITED_CODE);
  // Ours: the allowlist drifted or the wire model id is wrong. Not retryable.
  for (const s of [400, 404, 422]) {
    assert.equal(failed(s).status, 502, String(s));
    assert.equal(failed(s).code, DIRECT_ONLY_UPSTREAM_CODE);
  }
  // Our key rejected, the upstream down, or no status at all (socket error).
  for (const s of [401, 403, 500, 502, 503, undefined, 0]) {
    assert.equal(failed(s).status, 503, String(s));
    assert.equal(failed(s).code, DIRECT_ONLY_UNAVAILABLE_CODE);
  }
  // A failure outranks a skip: the attempt is what happened last.
  assert.equal(
    classify({ skipped: [{ provider: 'venice', reason: 'too_many_images', field: '1' }], failed: [{ provider: 'venice', status: 429 }] }).status,
    429,
  );
});

test('no message names an upstream provider', () => {
  const all = [
    skip('too_many_images', '1'), skip('non_text_content'), skip('unmappable_field', 'logit_bias'),
    skip('no_tunnel_or_key'), skip('whatever'), classify(),
    ...[429, 400, 500].map((status) => classify({ failed: [{ provider: 'venice', status }] })),
  ];
  for (const r of all) assert.doesNotMatch(r.message.replace(M, ''), /venice|openrouter/i, r.message);
});

test('firerouter ids are direct-only: Fireworks resolves the route, OpenRouter never sees it', () => {
  for (const m of ['firerouter/auto', 'firerouter/eco', 'firerouter/premium']) {
    assert.equal(isDirectOnlyModel(m), true, m);
    assert.deepEqual(directOnlyNamespaceFor(m), { prefix: 'firerouter/', provider: 'firerouter' });
  }
  // The bare alias is hp's to resolve; the enclave only ever sees the resolved id.
  assert.equal(isDirectOnlyModel('firerouter'), false);
  const r = classifyDirectOnlyRefusal({
    model: 'firerouter/eco',
    provider: 'firerouter',
    skipped: [{ provider: 'firerouter', reason: 'no_tunnel_or_key' }],
    failed: [],
  });
  assert.equal(r.status, 503);
  assert.equal(r.code, DIRECT_ONLY_UNAVAILABLE_CODE);
  assert.doesNotMatch(r.message, /fireworks|anthropic/i);
  const failed = classifyDirectOnlyRefusal({ model: 'firerouter/eco', provider: 'firerouter', skipped: [], failed: [{ provider: 'firerouter', status: 400 }] });
  assert.equal(failed.status, 502);
  assert.equal(failed.code, DIRECT_ONLY_UPSTREAM_CODE);
});
