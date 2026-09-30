// A passed-through upstream error body must not name the upstream or our
// account with it. Observed 2026-09-30 on enclave.ppq.ai, api.ppq.ai and the
// staging horse-power: OpenRouter's 400 for an unknown model id arrived at the
// client with `user_id: "org_…"` — OpenRouter's id for PayPerQ's organisation,
// one constant value on every request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import {
  MAX_ERROR_BODY_BYTES,
  sanitizeUpstreamErrorBody,
  sanitizedErrorStream,
  stripUpstreamIdentity,
} from '../src/upstreamErrorBody.mjs';

const OR_UNKNOWN_MODEL =
  '{"error":{"message":"nonexistent/model-xyz is not a valid model ID","code":400},"user_id":"org_test00000000000000000000"}';

function collect(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    stream.on('error', reject);
  });
}

test('drops the organisation id and keeps the error the client acts on', () => {
  const out = JSON.parse(sanitizeUpstreamErrorBody(OR_UNKNOWN_MODEL));
  assert.deepEqual(out, { error: { message: 'nonexistent/model-xyz is not a valid model ID', code: 400 } });
});

test('drops provider_name from error.metadata (and a top-level metadata), keeps raw', () => {
  const nested = JSON.stringify({
    error: { message: 'Provider returned error', code: 400, metadata: { provider_name: 'Anthropic', raw: 'prompt is too long' } },
    user_id: 'org_x',
  });
  assert.deepEqual(stripUpstreamIdentity(JSON.parse(nested)), {
    error: { message: 'Provider returned error', code: 400, metadata: { raw: 'prompt is too long' } },
  });
  const top = JSON.stringify({ error: { message: 'x', code: 500 }, metadata: { provider_name: 'OpenAI', raw: 'boom' } });
  assert.deepEqual(stripUpstreamIdentity(JSON.parse(top)).metadata, { raw: 'boom' });
});

test('rewords links, the docs pointer and the name; non-JSON gets only that', () => {
  const body = JSON.stringify({
    error: { message: 'Key limit exceeded. Please refer to our docs: https://openrouter.ai/docs/limits for OpenRouter limits', code: 402 },
    user_id: 'org_x',
  });
  const out = JSON.parse(sanitizeUpstreamErrorBody(body));
  assert.equal(/openrouter/i.test(out.error.message), false);
  assert.match(out.error.message, /AI Provider/);
  assert.equal(out.error.code, 402);
  assert.equal(sanitizeUpstreamErrorBody('<html>OpenRouter is down</html>'), '<html>AI Provider is down</html>');
  assert.equal(sanitizeUpstreamErrorBody('[1,2]'), '[1,2]');
  assert.equal(sanitizeUpstreamErrorBody(''), '');
});

test('keeps the JSON valid when a link is followed by a quote (CodeRabbit)', () => {
  // Serialized, the message reads `…/docs\\" is unavailable`. A wording pass
  // over the serialized text ate the backslash and the client got invalid JSON.
  const body = JSON.stringify({ error: { message: 'https://openrouter.ai/docs" is unavailable', code: 400 } });
  const out = JSON.parse(sanitizeUpstreamErrorBody(body));
  assert.equal(out.error.message, '" is unavailable');
  assert.equal(out.error.code, 400);
});

test('keeps a newline after a link, and the newlines of a multi-line raw diagnostic', () => {
  const body = JSON.stringify({
    error: {
      message: 'Rate limited. See https://openrouter.ai/docs/limits\nRetry shortly.',
      code: 429,
      metadata: { raw: 'line one\nline two\n\nline four' },
    },
  });
  const out = JSON.parse(sanitizeUpstreamErrorBody(body));
  assert.equal(out.error.message, 'Rate limited. See \nRetry shortly.');
  assert.equal(out.error.metadata.raw, 'line one\nline two\n\nline four');
});

test('rewords string values anywhere in the body, arrays included', () => {
  const body = JSON.stringify({ error: { message: 'x', code: 500, metadata: { raw: ['via OpenRouter', 7, null] } } });
  assert.deepEqual(JSON.parse(sanitizeUpstreamErrorBody(body)).error.metadata.raw, ['via AI Provider', 7, null]);
});

test('the stream wrapper sanitizes a body split across chunks, mid-key', async () => {
  const up = new PassThrough();
  const out = collect(sanitizedErrorStream(up, 400));
  // Split inside `"user_id"` and inside the org id: a per-chunk pass would miss both.
  const i = OR_UNKNOWN_MODEL.indexOf('user_') + 3;
  const j = OR_UNKNOWN_MODEL.indexOf('org_') + 6;
  up.write(OR_UNKNOWN_MODEL.slice(0, i));
  up.write(OR_UNKNOWN_MODEL.slice(i, j));
  up.end(OR_UNKNOWN_MODEL.slice(j));
  const text = await out;
  assert.equal(text.includes('org_'), false);
  assert.deepEqual(JSON.parse(text), { error: { message: 'nonexistent/model-xyz is not a valid model ID', code: 400 } });
});

test('the stream wrapper replaces an oversized "error" body rather than forwarding it', async () => {
  const up = new PassThrough();
  const out = collect(sanitizedErrorStream(up, 502));
  up.write(Buffer.alloc(MAX_ERROR_BODY_BYTES, 0x61));
  up.end('{"user_id":"org_x"}');
  assert.deepEqual(JSON.parse(await out), { error: { message: 'upstream error', code: 502 } });
});

test('a body too deeply nested to sanitize gets the generic body, not a dead stream', async () => {
  // Under the byte bound, over the recursion bound: JSON.parse succeeds and
  // sanitizeWordingDeep overflows the stack.
  const depth = 20_000;
  const text = '['.repeat(depth) + '0' + ']'.repeat(depth);
  assert.ok(text.length < MAX_ERROR_BODY_BYTES);
  assert.throws(() => sanitizeUpstreamErrorBody(text), RangeError, 'the probe body must actually overflow');
  const up = new PassThrough();
  const out = collect(sanitizedErrorStream(up, 400));
  up.end(text);
  assert.deepEqual(JSON.parse(await out), { error: { message: 'upstream error', code: 400 } });
});

test('an upstream error fails the wrapper instead of hanging it', async () => {
  const up = new PassThrough();
  const wrapped = sanitizedErrorStream(up, 500);
  const failed = new Promise((resolve) => wrapped.on('error', resolve));
  up.write('{"error":');
  up.destroy(new Error('socket reset'));
  assert.equal((await failed).message, 'socket reset');
});
