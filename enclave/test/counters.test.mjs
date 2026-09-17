import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCounters } from '../src/counters.mjs';

test('a fresh counter set snapshots to zeros with the documented shape', () => {
  assert.deepEqual(createCounters().snapshot(), {
    requests: 0,
    by_outcome: {},
    by_provider: {},
    ehbp: 0,
    streaming: 0,
    open_streams: 0,
    settle: { queued: 0, permanent_failures: 0 },
  });
});

test('increments land in the right buckets', () => {
  const c = createCounters();
  c.request();
  c.request();
  c.ehbp();
  c.streaming();
  c.streamOpened();
  c.streamOpened();
  c.streamClosed();
  c.outcome('clean');
  c.outcome('clean');
  c.outcome('authorize_rejected');
  c.provider('openrouter');
  c.provider('fireworks');
  c.provider('openrouter');
  c.settlePermanentFailure();
  assert.deepEqual(c.snapshot({ settleQueued: 3 }), {
    requests: 2,
    by_outcome: { clean: 2, authorize_rejected: 1 },
    by_provider: { openrouter: 2, fireworks: 1 },
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
  c.outcome('Invalid prompt: "hunter2"');
  c.outcome(undefined);
  c.outcome(42);
  c.provider('Fireworks AI');
  assert.deepEqual(c.snapshot().by_outcome, { other: 3 });
  assert.deepEqual(c.snapshot().by_provider, { other: 1 });
});

test('the key set is bounded: past the cap, new keys fold into `other`', () => {
  const c = createCounters();
  for (let i = 0; i < 100; i += 1) c.outcome(`code_${i}`);
  const keys = Object.keys(c.snapshot().by_outcome);
  assert.ok(keys.length <= 64, `${keys.length} keys`);
  assert.equal(c.snapshot().by_outcome.other, 100 - 63); // 63 real keys + other
  // Existing keys still count after the cap is reached.
  c.outcome('code_0');
  assert.equal(c.snapshot().by_outcome.code_0, 2);
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
  c.outcome('clean');
  const s = c.snapshot();
  s.by_outcome.clean = 99;
  s.requests = 99;
  assert.equal(c.snapshot().by_outcome.clean, 1);
  assert.equal(c.snapshot().requests, 0);
});
