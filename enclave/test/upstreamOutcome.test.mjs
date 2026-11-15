import test from 'node:test';
import assert from 'node:assert/strict';
import { UpstreamOutcomeDetector, readOutcomeLine, providerSlug, FINISH_REASONS } from '../src/upstreamOutcome.mjs';
import { createTraceRecorder, sanitizeUpstreamOutcome, OUTCOME_FINISH_REASONS } from '../src/trace.mjs';

const SECRET = 'my secret prompt about a divorce';
const enc = (s) => new TextEncoder().encode(s);

test('the finish-reason vocabulary is the documented closed set and trace.mjs agrees', () => {
  assert.deepEqual([...FINISH_REASONS], ['stop', 'length', 'content_filter', 'tool_calls', 'function_call', 'error']);
  assert.deepEqual([...OUTCOME_FINISH_REASONS], [...FINISH_REASONS]);
});

test('a clean OpenRouter stream yields the terminal finish reason and the native one', () => {
  const d = new UpstreamOutcomeDetector();
  d.feed(enc('data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}\n\n'));
  d.feed(enc('data: {"id":"gen-1","choices":[{"index":0,"delta":{"content":" there"},"finish_reason":null}]}\n\n'));
  d.feed(enc('data: {"id":"gen-1","choices":[{"index":0,"delta":{},"finish_reason":"stop","native_finish_reason":"STOP"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}\n\n'));
  d.feed(enc('data: [DONE]\n\n'));
  assert.deepEqual(d.finish(), { finish_reason: 'stop', native_finish_reason: 'STOP' });
});

test('a Meta policy rejection relayed as an in-band error frame is read as code + provider, never the message', () => {
  const d = new UpstreamOutcomeDetector();
  const frame = `data: {"error":{"message":"Provider returned error: ${SECRET}","code":403,"metadata":{"raw":"{\\"error\\":{\\"code\\":\\"user_blocked\\"}}","provider_name":"Meta"}},"user_id":"org_x"}\n\n`;
  // Split mid-frame to exercise line buffering.
  d.feed(enc(frame.slice(0, 40)));
  d.feed(enc(frame.slice(40)));
  const out = d.finish();
  assert.deepEqual(out, { error_code: 403, error_provider: 'meta' });
  assert.equal(JSON.stringify(out).includes('secret'), false);
});

test('a Vertex block reason and a content_filter finish are read from the structure', () => {
  assert.deepEqual(
    readOutcomeLine('{"promptFeedback":{"blockReason":"PROHIBITED_CONTENT"},"candidates":[]}'),
    { block_reason: 'PROHIBITED_CONTENT' },
  );
  assert.deepEqual(
    readOutcomeLine('data: {"choices":[{"delta":{},"finish_reason":"content_filter","native_finish_reason":"SAFETY"}]}'),
    { finish_reason: 'content_filter', native_finish_reason: 'SAFETY' },
  );
});

test('a key spelled inside a string value is not a member and does not match', () => {
  // The quote before a key inside a JSON string is escaped; the lookbehind refuses it.
  const line = `data: {"choices":[{"delta":{"content":"she typed \\"finish_reason\\": \\"error\\" and \\"blockReason\\": \\"X\\""},"finish_reason":null}]}`;
  assert.deepEqual(readOutcomeLine(line), {});
  const errInContent = `data: {"choices":[{"delta":{"content":"{\\"error\\": {\\"code\\": 500, \\"provider_name\\": \\"Evil\\"}}"},"finish_reason":null}]}`;
  assert.deepEqual(readOutcomeLine(errInContent), {});
});

test('values outside the vocabulary or the token shape are dropped', () => {
  assert.deepEqual(readOutcomeLine('{"finish_reason":"please stop"}'), {});
  assert.deepEqual(readOutcomeLine('{"finish_reason":"refused"}'), {});
  assert.deepEqual(readOutcomeLine('{"native_finish_reason":"has space"}'), {});
  assert.deepEqual(readOutcomeLine('{"blockReason":"a-b"}'), {});
  assert.deepEqual(readOutcomeLine('{"error":{"code":"ERR_X","provider_name":"Meta"}}'), { error_provider: 'meta' });
  assert.equal(providerSlug('Google AI Studio'), 'google-ai-studio');
  assert.equal(providerSlug('x'.repeat(41)), undefined);
  assert.equal(providerSlug('<script>'), undefined);
});

test('later frames override earlier ones member by member; a non-streaming body is one line', () => {
  const d = new UpstreamOutcomeDetector();
  d.feed('data: {"choices":[{"delta":{},"finish_reason":"length"}]}\n');
  d.feed('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n');
  assert.deepEqual(d.finish(), { finish_reason: 'stop' });
  const body = new UpstreamOutcomeDetector();
  body.feed(`{"id":"x","choices":[{"message":{"content":"${'y'.repeat(100_000)}"},"finish_reason":"content_filter"}],"usage":{}}`);
  assert.deepEqual(body.finish(), { finish_reason: 'content_filter' });
});

test('an oversized content line is inspected only on its tail and never retained whole', () => {
  const d = new UpstreamOutcomeDetector();
  d.feed('data: {"choices":[{"delta":{"content":"' + SECRET.repeat(20_000) + '"},"finish_reason":null}]}');
  assert.ok(d.pending.length <= 8 * 1024, 'pending is bounded');
  assert.equal(d.finish(), undefined);
});

test('the provider\'s own frames keep the verdict a translator would fold into stop', () => {
  // Anthropic Messages SSE: a refusal ends with stop_reason: refusal.
  const a = new UpstreamOutcomeDetector();
  a.feed('event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_sequence":null},"usage":{"output_tokens":3}}\n\n');
  assert.deepEqual(a.finish(), { native_finish_reason: 'refusal' });
  // Responses API: the terminal object says incomplete_details.reason content_filter.
  const r = new UpstreamOutcomeDetector();
  r.feed('event: response.incomplete\ndata: {"type":"response.incomplete","response":{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"content_filter"},"output":[]}}\n\n');
  assert.deepEqual(r.finish(), { finish_reason: 'content_filter' });
  const m = new UpstreamOutcomeDetector();
  m.feed('data: {"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"}}}\n');
  assert.equal(m.finish(), undefined);
});

test('the error code and provider are read from the error object, not from a later sibling', () => {
  const line = '{"error":{"message":"x"},"usage":{"code":500},"meta":{"provider_name":"Later Sibling"}}';
  assert.deepEqual(readOutcomeLine(line), {});
  const far = '{"error":{"message":"' + 'y'.repeat(2000) + '","code":403,"metadata":{"provider_name":"Meta"}}}';
  assert.deepEqual(readOutcomeLine(far), {}, 'a code past the bounded span is not attributed');
  // A brace inside the message string does not end the object early.
  const braces = '{"error":{"message":"see {this} and }","code":429,"metadata":{"provider_name":"Groq"}},"code":500}';
  assert.deepEqual(readOutcomeLine(braces), { error_code: 429, error_provider: 'groq' });
});

test('the recorder carries the outcome through build() under the same bounds', () => {
  const rec = createTraceRecorder();
  rec.setUpstreamOutcome({ finish_reason: 'content_filter', native_finish_reason: 'PROHIBITED_CONTENT', error_code: 403, error_provider: 'meta', message: SECRET });
  const t = rec.build();
  assert.deepEqual(t.upstream_outcome, {
    finish_reason: 'content_filter',
    native_finish_reason: 'PROHIBITED_CONTENT',
    error_code: 403,
    error_provider: 'meta',
  });
  assert.equal(JSON.stringify(t).includes('secret'), false);
  assert.equal(createTraceRecorder().build().upstream_outcome, undefined);
});

test('sanitizeUpstreamOutcome drops prose and out-of-range codes', () => {
  assert.equal(sanitizeUpstreamOutcome({ finish_reason: SECRET, native_finish_reason: SECRET, block_reason: 'has space', error_code: 42, error_provider: SECRET }), undefined);
  assert.deepEqual(sanitizeUpstreamOutcome({ error_code: 599, finish_reason: 'error' }), { error_code: 599, finish_reason: 'error' });
  assert.equal(sanitizeUpstreamOutcome({ error_code: 600 }), undefined);
  assert.equal(sanitizeUpstreamOutcome('stop'), undefined);
});
