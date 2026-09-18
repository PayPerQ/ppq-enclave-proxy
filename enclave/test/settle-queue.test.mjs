import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifySettleStatus,
  backoffMs,
  createSettleQueue,
} from '../src/settleQueue.mjs';

const tick = () => new Promise((r) => setTimeout(r, 0));

/** Fake `post`: returns queued outcomes in order; records calls. */
function fakePost(outcomes) {
  let i = 0;
  const calls = [];
  const fn = (meta) => {
    calls.push(meta);
    const o = typeof outcomes === 'function' ? outcomes(i, meta) : outcomes[Math.min(i, outcomes.length - 1)];
    i += 1;
    return Promise.resolve(o);
  };
  fn.calls = calls;
  return fn;
}

// A no-op timer so no real interval fires; tests drive drainTick() manually.
const noTimer = () => 0;

test('classifySettleStatus maps statuses to retry decisions', () => {
  assert.equal(classifySettleStatus(200), 'ok');
  assert.equal(classifySettleStatus(204), 'ok');
  assert.equal(classifySettleStatus(400), 'permanent'); // bad payload
  assert.equal(classifySettleStatus(401), 'permanent'); // bad enclave secret
  assert.equal(classifySettleStatus(500), 'transient'); // billing error (rolled back)
  assert.equal(classifySettleStatus(502), 'transient');
  assert.equal(classifySettleStatus(0), 'transient'); // no response
});

test('backoffMs grows exponentially and caps', () => {
  assert.equal(backoffMs(1), 2000);
  assert.equal(backoffMs(2), 4000);
  assert.equal(backoffMs(3), 8000);
  assert.equal(backoffMs(20), 120000); // capped
});

test('a successful settle is never queued', async () => {
  const post = fakePost(['ok']);
  const q = createSettleQueue({ post, setTimer: noTimer });
  await q.submit({ request_id: 'r-ok' });
  assert.equal(q.size(), 0);
  assert.equal(post.calls.length, 1);
});

test('a permanent failure is not retried', async () => {
  const logs = [];
  const post = fakePost(['permanent']);
  const q = createSettleQueue({ post, setTimer: noTimer, log: (m) => logs.push(m) });
  await q.submit({ request_id: 'r-bad' });
  assert.equal(q.size(), 0);
  assert.equal(post.calls.length, 1);
  assert.ok(logs.some((m) => m.includes('PERMANENT-FAIL')));
});

test('transient failures retry with backoff until acked', async () => {
  let clock = 0;
  const now = () => clock;
  const post = fakePost(['transient', 'transient', 'ok']);
  const q = createSettleQueue({ post, now, setTimer: noTimer, maxAttempts: 5 });

  await q.submit({ request_id: 'r1' }); // attempt 1 → transient → queued, nextAt = backoff(1)=2000
  assert.equal(q.size(), 1);

  clock = 1999;
  q.drainTick();
  await tick();
  assert.equal(q.size(), 1, 'not due yet → untouched');
  assert.equal(post.calls.length, 1);

  clock = 2000;
  q.drainTick();
  await tick(); // attempt 2 → transient → nextAt = 2000 + backoff(2)=6000
  assert.equal(q.size(), 1);
  assert.equal(post.calls.length, 2);

  clock = 6000;
  q.drainTick();
  await tick(); // attempt 3 → ok → removed
  assert.equal(q.size(), 0);
  assert.equal(post.calls.length, 3);
});

test('gives up (and logs lost revenue) after maxAttempts', async () => {
  let clock = 0;
  const now = () => clock;
  const logs = [];
  const post = fakePost(() => 'transient'); // never succeeds
  const q = createSettleQueue({
    post,
    now,
    setTimer: noTimer,
    maxAttempts: 3,
    log: (m) => logs.push(m),
  });

  await q.submit({ request_id: 'r-lost' }); // attempts = 1
  for (let k = 0; k < 10 && q.size() > 0; k += 1) {
    clock += 1_000_000; // always past nextAt
    q.drainTick();
    await tick();
  }
  assert.equal(q.size(), 0);
  assert.ok(logs.some((m) => m.includes('GAVE UP')));
});

test('queue is bounded — drops oldest beyond cap', async () => {
  const logs = [];
  const post = fakePost(() => 'transient');
  const q = createSettleQueue({ post, setTimer: noTimer, cap: 2, log: (m) => logs.push(m) });

  await q.submit({ request_id: 'a' });
  await q.submit({ request_id: 'b' });
  await q.submit({ request_id: 'c' }); // pushes past cap → drop oldest ('a')

  assert.equal(q.size(), 2);
  assert.ok(logs.some((m) => m.includes('queue full') && m.includes('a')));
});

// ── loss reporting (onPermanentFailure) ────────────────────────────────────
//
// A settle the queue will never deliver is revenue lost silently. The queue
// hands every such item to an injected reporter (server.mjs turns it into a
// `settle_failed_permanent` error report) rather than importing server state.

test('a permanent failure on submit is reported once with its meta', async () => {
  const seen = [];
  const post = fakePost(['permanent']);
  const q = createSettleQueue({ post, setTimer: noTimer, onPermanentFailure: (m, r) => seen.push([m, r]) });
  const meta = { request_id: 'r-bad', credit_id: 'c1', trace: { streaming: true } };
  await q.submit(meta);
  assert.deepEqual(seen, [[meta, 'permanent']]);
});

test('a permanent failure on a retry is reported and the item dropped', async () => {
  let clock = 0;
  const seen = [];
  const post = fakePost(['transient', 'permanent']);
  const q = createSettleQueue({
    post,
    now: () => clock,
    setTimer: noTimer,
    onPermanentFailure: (m, r) => seen.push([m.request_id, r]),
  });
  await q.submit({ request_id: 'r-late' });
  assert.deepEqual(seen, []);
  clock = 1_000_000;
  q.drainTick();
  await tick();
  assert.equal(q.size(), 0);
  assert.deepEqual(seen, [['r-late', 'permanent']]);
});

test('giving up after maxAttempts is reported as gave_up', async () => {
  let clock = 0;
  const seen = [];
  const post = fakePost(() => 'transient');
  const q = createSettleQueue({
    post,
    now: () => clock,
    setTimer: noTimer,
    maxAttempts: 2,
    onPermanentFailure: (m, r) => seen.push([m.request_id, r]),
  });
  await q.submit({ request_id: 'r-lost' });
  for (let k = 0; k < 10 && q.size() > 0; k += 1) {
    clock += 1_000_000;
    q.drainTick();
    await tick();
  }
  assert.deepEqual(seen, [['r-lost', 'gave_up']]);
});

test('an item dropped by the cap is reported as dropped', async () => {
  const seen = [];
  const post = fakePost(() => 'transient');
  const q = createSettleQueue({
    post,
    setTimer: noTimer,
    cap: 1,
    onPermanentFailure: (m, r) => seen.push([m.request_id, r]),
  });
  await q.submit({ request_id: 'a' });
  await q.submit({ request_id: 'b' });
  assert.deepEqual(seen, [['a', 'dropped']]);
  assert.equal(q.size(), 1);
});

test('a successful or transient-then-ok settle is never reported', async () => {
  let clock = 0;
  const seen = [];
  const post = fakePost(['transient', 'ok']);
  const q = createSettleQueue({
    post,
    now: () => clock,
    setTimer: noTimer,
    onPermanentFailure: (m) => seen.push(m),
  });
  await q.submit({ request_id: 'r' });
  clock = 1_000_000;
  q.drainTick();
  await tick();
  assert.equal(q.size(), 0);
  assert.deepEqual(seen, []);
});

test('a throwing reporter is swallowed and logged; the queue keeps working', async () => {
  const logs = [];
  const post = fakePost(['permanent', 'ok']);
  const q = createSettleQueue({
    post,
    setTimer: noTimer,
    log: (m) => logs.push(m),
    onPermanentFailure: () => {
      throw new Error('reporter broke');
    },
  });
  assert.equal(await q.submit({ request_id: 'r1' }), 'permanent');
  assert.equal(await q.submit({ request_id: 'r2' }), 'ok');
  assert.ok(logs.some((m) => m.includes('reporter threw')));
});

test('the reporter is optional', async () => {
  const q = createSettleQueue({ post: fakePost(['permanent']), setTimer: noTimer });
  assert.equal(await q.submit({ request_id: 'r' }), 'permanent');
});
