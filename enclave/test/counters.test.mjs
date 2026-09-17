import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCounters } from '../src/counters.mjs';

const sum = (m) => Object.values(m).reduce((a, b) => a + b, 0);

test('a fresh counter set snapshots to zeros with the documented shape', () => {
  assert.deepEqual(createCounters().snapshot(), {
    requests: 0,
    by_outcome: {},
    by_provider: {},
    error_reports: {},
    ehbp: 0,
    streaming: 0,
    open_streams: 0,
    settle: { queued: 0, permanent_failures: 0 },
  });
});

test('increments land in the right buckets', () => {
  const c = createCounters();
  c.beginRequest()('clean');
  c.beginRequest()('clean');
  c.ehbp();
  c.streaming();
  c.streamOpened();
  c.streamOpened();
  c.streamClosed();
  c.errorReport('upstream_error_status');
  c.provider('openrouter');
  c.provider('fireworks');
  c.provider('openrouter');
  c.settlePermanentFailure();
  assert.deepEqual(c.snapshot({ settleQueued: 3 }), {
    requests: 2,
    by_outcome: { clean: 2 },
    by_provider: { openrouter: 2, fireworks: 1 },
    error_reports: { upstream_error_status: 1 },
    ehbp: 1,
    streaming: 1,
    open_streams: 1,
    settle: { queued: 3, permanent_failures: 1 },
  });
});

test('open_streams never goes negative', () => {
  const c = createCounters();
  c.streamClosed();
  c.streamClosed();
  assert.equal(c.snapshot().open_streams, 0);
  c.streamOpened();
  c.streamClosed();
  c.streamClosed();
  assert.equal(c.snapshot().open_streams, 0);
});

test('keys that are not enum-shaped are counted under `other`, never echoed', () => {
  const c = createCounters();
  c.beginRequest()('Invalid prompt: "hunter2"');
  c.beginRequest()(undefined);
  c.beginRequest()(42);
  c.errorReport('Not A Code');
  c.provider('Fireworks AI');
  assert.deepEqual(c.snapshot().by_outcome, { other: 3 });
  assert.deepEqual(c.snapshot().error_reports, { other: 1 });
  assert.deepEqual(c.snapshot().by_provider, { other: 1 });
});

test('the key set is bounded: past the cap, new keys fold into `other`', () => {
  const c = createCounters();
  for (let i = 0; i < 100; i += 1) c.errorReport(`code_${i}`);
  const keys = Object.keys(c.snapshot().error_reports);
  assert.ok(keys.length <= 64, `${keys.length} keys`);
  assert.equal(c.snapshot().error_reports.other, 100 - 63); // 63 named keys + other
  // Existing keys still count after the cap is reached.
  c.errorReport('code_0');
  assert.equal(c.snapshot().error_reports.code_0, 2);
});

test('settle.queued is read from the caller and coerced to a non-negative integer', () => {
  const c = createCounters();
  assert.equal(c.snapshot({ settleQueued: -1 }).settle.queued, 0);
  assert.equal(c.snapshot({ settleQueued: 2.9 }).settle.queued, 2);
  assert.equal(c.snapshot({ settleQueued: NaN }).settle.queued, 0);
  assert.equal(c.snapshot({ settleQueued: '5' }).settle.queued, 0);
});

test('snapshots are copies: mutating one does not touch the counters', () => {
  const c = createCounters();
  c.beginRequest()('clean');
  const s = c.snapshot();
  s.by_outcome.clean = 99;
  s.requests = 99;
  assert.equal(c.snapshot().by_outcome.clean, 1);
  assert.equal(c.snapshot().requests, 0 + 1);
});

// ── one outcome per request ───────────────────────────────────────────────
//
// server.mjs calls beginRequest() once per chat request and the returned
// finalize on every early return, when a passed-through upstream error status
// is the answer, and at the terminal stream end. Error reports are counted
// separately and a request may send several, so they must never be outcomes.

test('finalize records exactly one outcome; later calls are no-ops', () => {
  const c = createCounters();
  const finalize = c.beginRequest();
  finalize('upstream_error_status'); // passed-through 4xx
  finalize('clean'); // ...which then streams to a clean end
  finalize('client_abort');
  assert.deepEqual(c.snapshot().by_outcome, { upstream_error_status: 1 });
  assert.equal(c.snapshot().requests, 1);
});

test('a request that never finalizes still counts as a request (in flight)', () => {
  const c = createCounters();
  c.beginRequest();
  assert.equal(c.snapshot().requests, 1);
  assert.deepEqual(c.snapshot().by_outcome, {});
});

test('error reports are telemetry, not outcomes: by_outcome sums to requests across the CodeRabbit sequence', () => {
  const c = createCounters();
  // 1. clean chat
  { const f = c.beginRequest(); f('clean'); }
  // 2. client aborts mid-stream: CLIENT_ABORT report, then the stream end
  { const f = c.beginRequest(); c.errorReport('client_abort'); f('client_abort'); }
  // 3. upstream dies: STREAM_FAILED report, then the error end
  { const f = c.beginRequest(); c.errorReport('stream_failed'); f('upstream_error'); }
  // 4. refused at authorize: report + early return
  { const f = c.beginRequest(); c.errorReport('authorize_rejected'); f('authorize_rejected'); }
  // 5. a passed-through 4xx that then ends clean: report, early finalize, no-op end
  { const f = c.beginRequest(); c.errorReport('upstream_error_status'); f('upstream_error_status'); f('clean'); }
  // 6. a direct candidate skipped (binding violation report) before OpenRouter serves cleanly
  { const f = c.beginRequest(); c.errorReport('upstream_unreachable'); f('clean'); }
  // 7. missing credential: no report at all, outcome 'unauthenticated'
  { const f = c.beginRequest(); f('unauthenticated'); }
  // 8. a settle that fails permanently, long after request 1 ended
  c.settlePermanentFailure();
  c.errorReport('settle_failed_permanent');
  // 9. an unanticipated throw
  { const f = c.beginRequest(); c.errorReport('internal_error'); f('internal_error'); }

  const s = c.snapshot();
  assert.equal(s.requests, 8);
  assert.deepEqual(s.by_outcome, {
    clean: 2,
    client_abort: 1,
    upstream_error: 1,
    authorize_rejected: 1,
    upstream_error_status: 1,
    unauthenticated: 1,
    internal_error: 1,
  });
  assert.equal(sum(s.by_outcome), s.requests);
  assert.deepEqual(s.error_reports, {
    client_abort: 1,
    stream_failed: 1,
    authorize_rejected: 1,
    upstream_error_status: 1,
    upstream_unreachable: 1,
    settle_failed_permanent: 1,
    internal_error: 1,
  });
  assert.equal(s.settle.permanent_failures, 1);
  // Settle losses are not outcomes and not requests.
  assert.equal('settle_failed_permanent' in s.by_outcome, false);
});
