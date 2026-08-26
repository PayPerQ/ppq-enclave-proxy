import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ERROR_CODES, buildErrorReport } from '../src/errorReport.mjs';

// The report body is a containment boundary. This enclave is the one component
// that sees prompts in the clear, and upstream providers quote request content
// back inside their error bodies — so these tests exist to prove that whatever a
// caller passes, only allowlisted fields in an allowlisted shape come out.

test('builds a report for a known code', () => {
  assert.deepEqual(
    buildErrorReport(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: 'req-11-irvnbx',
      credit_id: '681c9823-3778-432b-95af-7f2a4db204f5',
      model: 'anthropic/claude-opus-5',
      provider: 'Fireworks',
      upstream_status: 503,
      query_source: 'ui',
    }),
    {
      code: 'upstream_unreachable',
      request_id: 'req-11-irvnbx',
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

test('bounds a long identifier rather than passing it through', () => {
  const body = buildErrorReport(ERROR_CODES.MODEL_REJECTED, { model: 'a'.repeat(500) });
  assert.equal(body.model.length, 96);
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
