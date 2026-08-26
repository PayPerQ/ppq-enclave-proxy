import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ERROR_CODES,
  buildErrorReport,
  classifyModelRejection,
} from '../src/errorReport.mjs';

// The report body is a containment boundary. This enclave is the one component
// that sees prompts in the clear, and upstream providers quote request content
// back inside their error bodies — so these tests exist to prove that whatever a
// caller passes, only allowlisted fields in an allowlisted shape come out.

test('builds a report for a known code', () => {
  assert.deepEqual(
    buildErrorReport(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: 'enc-1787574285876-k3d9f1',
      credit_id: '681c9823-3778-432b-95af-7f2a4db204f5',
      model: 'anthropic/claude-opus-5',
      provider: 'Fireworks',
      upstream_status: 503,
      query_source: 'ui',
    }),
    {
      code: 'upstream_unreachable',
      request_id: 'enc-1787574285876-k3d9f1',
      credit_id: '681c9823-3778-432b-95af-7f2a4db204f5',
      model: 'anthropic/claude-opus-5',
      provider: 'Fireworks',
      query_source: 'ui',
      upstream_status: 503,
    },
  );
});

test('refuses an unknown code outright', () => {
  assert.equal(buildErrorReport('something_new', { model: 'a/b' }), null);
  assert.equal(buildErrorReport('', {}), null);
  assert.equal(buildErrorReport(undefined, {}), null);
});

// The leak this design exists to prevent: a caller passing an upstream error
// message through as if it were an identifier.
test('drops sentence-shaped values instead of forwarding them', () => {
  const body = buildErrorReport(ERROR_CODES.TRANSFORM_FAILED, {
    model: 'Invalid prompt: "my bank password is hunter2"',
    provider: 'failed after the user asked about X',
    request_id: 'has spaces',
  });
  assert.deepEqual(body, { code: 'transform_failed' });
});

test('ignores any field not on the allowlist', () => {
  const body = buildErrorReport(ERROR_CODES.STREAM_FAILED, {
    model: 'x-ai/grok-4.6',
    messages: [{ role: 'user', content: 'secret' }],
    prompt: 'secret',
    error: 'upstream said: secret',
    stack: 'at foo (bar.mjs:1)',
  });
  assert.deepEqual(body, { code: 'stream_failed', model: 'x-ai/grok-4.6' });
});

// Codex review: slicing to 96 and validating the stub accepts a long value
// whose first 96 chars happen to be slug-shaped — looser than "is a model id".
test('refuses an overlength identifier instead of truncating it into a pass', () => {
  assert.deepEqual(buildErrorReport(ERROR_CODES.MODEL_REJECTED, { model: 'a'.repeat(500) }), {
    code: 'model_rejected',
  });
  assert.equal(buildErrorReport(ERROR_CODES.MODEL_REJECTED, { model: 'a'.repeat(96) }).model.length, 96);
});

// `requestId` in server.mjs falls back to the caller's x-request-id header.
test('accepts only enclave-generated request ids', () => {
  const ours = 'enc-1787574285876-k3d9f1';
  assert.equal(buildErrorReport(ERROR_CODES.STREAM_FAILED, { request_id: ours }).request_id, ours);
  for (const theirs of ['req-11-irvnbx', 'my-own-id', 'enc-1-x', '']) {
    const body = buildErrorReport(ERROR_CODES.STREAM_FAILED, { request_id: theirs });
    assert.equal('request_id' in body, false, `leaked ${theirs}`);
  }
});

test('classifies why a model was rejected without touching the value', () => {
  assert.equal(
    classifyModelRejection('Invalid payload: model must be a string'),
    ERROR_CODES.MODEL_REJECTED_NOT_STRING,
  );
  assert.equal(
    classifyModelRejection('Smart-routing models are not yet supported by the enclave proxy'),
    ERROR_CODES.MODEL_REJECTED_SMART_ROUTING,
  );
  assert.equal(
    classifyModelRejection('private/* models use the Tinfoil path, not this proxy'),
    ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH,
  );
  // An unrecognised message degrades to the generic code, never forwarded.
  assert.equal(classifyModelRejection('something new about "the prompt"'), ERROR_CODES.MODEL_REJECTED);
  assert.equal(classifyModelRejection(undefined), ERROR_CODES.MODEL_REJECTED);
});

test('omits a non-numeric upstream status', () => {
  for (const status of ['503', 'oops', null, undefined, NaN, Infinity]) {
    const body = buildErrorReport(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      upstream_status: status,
    });
    // '503' is deliberately included: Number('503') is finite, so a numeric
    // string is coerced rather than dropped. Anything non-numeric is absent.
    if (status === '503') assert.equal(body.upstream_status, 503);
    else assert.equal('upstream_status' in body, false);
  }
});

test('a report with nothing usable is still a valid report', () => {
  // Losing the identifiers must not lose the fact that something failed.
  assert.deepEqual(buildErrorReport(ERROR_CODES.REQUEST_UNREADABLE, {}), {
    code: 'request_unreadable',
  });
});

test('every exported code is accepted by the builder', () => {
  for (const code of Object.values(ERROR_CODES)) {
    assert.deepEqual(buildErrorReport(code, {}), { code });
  }
});
