// The spend cap bounds the OUTPUT a request can ask for: the per-choice
// length (max_tokens / max_completion_tokens) AND the number of choices (`n`).
// Before Oct 2026 only the length was clamped, so `n` multiplied the cap
// (Oct 17-19 security reports: Malik Werkudhara, Risky Dwi Saputra).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applySpendCap } from '../src/routing.mjs';
import { createTraceRecorder } from '../src/trace.mjs';

const CAP = 100;

test('length: max_tokens is clamped to the cap, as before', () => {
  const p = { max_tokens: 4000 };
  assert.deepEqual(applySpendCap(p, CAP), { n: undefined });
  assert.equal(p.max_tokens, 100);
  assert.equal('n' in p, false, 'no n was sent, none is added');
});

test('length: max_completion_tokens-only body keeps its own field', () => {
  const p = { max_completion_tokens: 4000 };
  applySpendCap(p, CAP);
  assert.equal(p.max_completion_tokens, 100);
  assert.equal(p.max_tokens, undefined);
});

test('length: both fields present are both clamped; neither present gets max_tokens = cap', () => {
  const both = { max_tokens: 500, max_completion_tokens: 600 };
  applySpendCap(both, CAP);
  assert.deepEqual(both, { max_tokens: 100, max_completion_tokens: 100 });
  const neither = {};
  applySpendCap(neither, CAP);
  assert.deepEqual(neither, { max_tokens: 100 });
});

test('n: a request at the full cap gets exactly one completion', () => {
  const p = { max_tokens: 4000, n: 8 };
  assert.deepEqual(applySpendCap(p, CAP), { n: 1 });
  assert.deepEqual(p, { max_tokens: 100, n: 1 });
});

test('n: survives only within the headroom the cap leaves (floor division)', () => {
  const p = { max_tokens: 30, n: 8 };
  assert.deepEqual(applySpendCap(p, CAP), { n: 3 });
  assert.deepEqual(p, { max_tokens: 30, n: 3 }, '3 * 30 = 90 <= 100; 4 * 30 would not fit');
});

test('n: left alone when n * length already fits', () => {
  const p = { max_tokens: 20, n: 5 };
  assert.deepEqual(applySpendCap(p, CAP), { n: undefined });
  assert.deepEqual(p, { max_tokens: 20, n: 5 });
});

test('n: bounded against the max_completion_tokens-only body too (no NaN)', () => {
  const p = { max_completion_tokens: 50, n: 8 };
  assert.deepEqual(applySpendCap(p, CAP), { n: 2 });
  assert.deepEqual(p, { max_completion_tokens: 50, n: 2 });
});

test('n: no length sent means the cap is the per-choice length, so n becomes 1', () => {
  const p = { n: 8 };
  assert.deepEqual(applySpendCap(p, CAP), { n: 1 });
  assert.deepEqual(p, { max_tokens: 100, n: 1 });
});

test('n: values that are not positive integers are dropped, not forwarded for coercion', () => {
  for (const bad of [0, -1, '8', 2.5, null, true, {}]) {
    const p = { max_tokens: 10, n: bad };
    assert.deepEqual(applySpendCap(p, CAP), { n: undefined }, `n=${JSON.stringify(bad)}`);
    assert.equal('n' in p, false, `n=${JSON.stringify(bad)} is removed`);
  }
  const one = { max_tokens: 10, n: 1 };
  applySpendCap(one, CAP);
  assert.equal(one.n, 1, 'an explicit 1 is kept verbatim');
});

test('trace: the bounded n is recorded beside the cap, only when it was reduced', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setMaxTokensCap({ applied: true, cap: CAP });
  assert.equal('max_tokens_cap_n' in rec.build(), false);
  rec.setMaxTokensCap({ applied: true, cap: CAP, n: 3 });
  assert.equal(rec.build().max_tokens_cap_n, 3);
  rec.setMaxTokensCap({ applied: true, cap: CAP, n: 0 });
  assert.equal('max_tokens_cap_n' in rec.build(), false, 'a non-positive value is not a bound');
});
