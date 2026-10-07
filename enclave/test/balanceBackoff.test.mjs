import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BALANCE_BACKOFF_CODE,
  MAX_RETRY_AFTER_SECONDS,
  MAX_TRACKED_CREDENTIALS,
  createBalanceBackoff,
  isBalanceBackoffRefusal,
  presentedCredentialKey,
  retryAfterSeconds,
} from '../src/balanceBackoff.mjs';

// hp #1022: the enclave remembers hp's 429 balance backoff per presented
// credential and answers repeats itself. These pin the key (hp's precedence,
// hashed, never the secret), what is honoured (hp's window, capped), and the
// one refusal that qualifies.

const KEY = 'sk-0EOqd4re2hjgcz9r7I9Aku';
const CREDIT_ID = '1d879f5e-7981-49b6-8a98-e4a41233f8c7';
const BODY = { error: 'Insufficient credit on credit id 1d879f5e…. Please top up.', code: BALANCE_BACKOFF_CODE, retry_after_seconds: 60 };

test('presentedCredentialKey: hp precedence, hashed, never the secret', () => {
  const bearer = presentedCredentialKey({ authorization: `Bearer ${KEY}` });
  assert.match(bearer, /^[0-9a-f]{64}$/);
  assert.ok(!bearer.includes(KEY));
  // Case-insensitive scheme, same key.
  assert.equal(presentedCredentialKey({ authorization: `bearer ${KEY}` }), bearer);
  // Bearer wins over everything.
  assert.equal(presentedCredentialKey({ authorization: `Bearer ${KEY}`, 'x-credit-id': CREDIT_ID, 'x-api-key': 'sk-other' }), bearer);
  // Without a Bearer, the credit id beats x-api-key (hp drops x-api-key then).
  const credit = presentedCredentialKey({ 'x-credit-id': CREDIT_ID, 'x-api-key': 'sk-other' });
  assert.equal(credit, presentedCredentialKey({ 'x-credit-id': CREDIT_ID }));
  assert.notEqual(credit, presentedCredentialKey({ 'x-api-key': 'sk-other' }));
  // A non-Bearer Authorization falls through to the credit id, as on hp.
  assert.equal(presentedCredentialKey({ authorization: 'Basic abc', 'x-credit-id': CREDIT_ID }), credit);
  // x-api-key alone is a credential; the same key as a Bearer is the same account.
  assert.equal(presentedCredentialKey({ 'x-api-key': KEY }), bearer);
  // Nothing presented → null.
  assert.equal(presentedCredentialKey({}), null);
  assert.equal(presentedCredentialKey(undefined), null);
  assert.equal(presentedCredentialKey({ authorization: 'Basic abc' }), null);
  assert.equal(presentedCredentialKey({ 'x-credit-id': '' }), null);
});

test('retryAfterSeconds: header first, body fallback, integer 1..60', () => {
  assert.equal(retryAfterSeconds('60', undefined), 60);
  assert.equal(retryAfterSeconds('15', 60), 15);
  assert.equal(retryAfterSeconds(undefined, 30), 30);
  assert.equal(retryAfterSeconds(undefined, '45'), 45);
  assert.equal(retryAfterSeconds('900', undefined), MAX_RETRY_AFTER_SECONDS);
  assert.equal(retryAfterSeconds(undefined, 7.9), 7);
  assert.equal(retryAfterSeconds('0', 0), null);
  assert.equal(retryAfterSeconds('-5', undefined), null);
  assert.equal(retryAfterSeconds('Wed, 21 Oct 2026 07:28:00 GMT', undefined), null);
  assert.equal(retryAfterSeconds('soon', 'later'), null);
  assert.equal(retryAfterSeconds(undefined, undefined), null);
  assert.equal(retryAfterSeconds(undefined, null), null);
});

test('isBalanceBackoffRefusal: only a 429 carrying hp’s balance_backoff code', () => {
  assert.equal(isBalanceBackoffRefusal(429, BODY), true);
  assert.equal(isBalanceBackoffRefusal(402, BODY), false);
  assert.equal(isBalanceBackoffRefusal(429, { error: { code: 'credential_rate_limit' } }), false);
  assert.equal(isBalanceBackoffRefusal(429, { code: 'something_else' }), false);
  assert.equal(isBalanceBackoffRefusal(429, null), false);
  assert.equal(isBalanceBackoffRefusal(429, 'balance_backoff'), false);
  assert.equal(isBalanceBackoffRefusal(undefined, BODY), false);
});

test('remember + lookup: answers locally for exactly hp’s window, with the seconds left', () => {
  let t = 1_791_300_000_000;
  const bb = createBalanceBackoff({ now: () => t });
  const key = presentedCredentialKey({ authorization: `Bearer ${KEY}` });

  assert.equal(bb.lookup(key), null);
  assert.equal(bb.remember(key, { seconds: 60, body: BODY }), true);
  assert.deepEqual(bb.lookup(key), { status: 429, body: BODY, seconds: 60 });

  t += 12_300;
  assert.deepEqual(bb.lookup(key), { status: 429, body: BODY, seconds: 48 }); // 47.7 rounded up
  t += 47_600; // 59.9 s in: still held, and never told less than 1 s
  assert.deepEqual(bb.lookup(key), { status: 429, body: BODY, seconds: 1 });
  t += 100; // exactly 60 s: released
  assert.equal(bb.lookup(key), null);
  assert.equal(bb.size(), 0);
  // Another credential was never affected.
  assert.equal(bb.lookup(presentedCredentialKey({ 'x-credit-id': CREDIT_ID })), null);
});

test('remember: honours only what retryAfterSeconds would produce', () => {
  const bb = createBalanceBackoff({ now: () => 0 });
  assert.equal(bb.remember('k', { seconds: 0, body: BODY }), false);
  assert.equal(bb.remember('k', { seconds: MAX_RETRY_AFTER_SECONDS + 1, body: BODY }), false);
  assert.equal(bb.remember('k', { seconds: 30.5, body: BODY }), false);
  assert.equal(bb.remember('', { seconds: 30, body: BODY }), false);
  assert.equal(bb.remember(null, { seconds: 30, body: BODY }), false);
  assert.equal(bb.size(), 0);
  assert.equal(bb.remember('k', { seconds: MAX_RETRY_AFTER_SECONDS, body: BODY }), true);
  assert.equal(bb.size(), 1);
});

test('a later refusal re-arms the window; it never extends past hp’s latest answer', () => {
  let t = 0;
  const bb = createBalanceBackoff({ now: () => t });
  bb.remember('k', { seconds: 60, body: BODY });
  t = 50_000;
  bb.remember('k', { seconds: 10, body: { ...BODY, retry_after_seconds: 10 } });
  t = 59_000;
  assert.equal(bb.lookup('k').seconds, 1);
  t = 60_000;
  assert.equal(bb.lookup('k'), null);
});

test('bounded: past the cap the oldest credential is forgotten, never unbounded memory', () => {
  let t = 0;
  const bb = createBalanceBackoff({ now: () => t });
  for (let i = 0; i < MAX_TRACKED_CREDENTIALS; i += 1) bb.remember(`key-${i}`, { seconds: 60, body: BODY });
  assert.equal(bb.size(), MAX_TRACKED_CREDENTIALS);
  // Nothing expired yet, so the oldest goes.
  bb.remember('newest', { seconds: 60, body: BODY });
  assert.equal(bb.size(), MAX_TRACKED_CREDENTIALS);
  assert.equal(bb.lookup('key-0'), null);
  assert.notEqual(bb.lookup('newest'), null);
  // Expired entries are swept first when the cap is hit.
  t = 61_000;
  bb.remember('after-expiry', { seconds: 60, body: BODY });
  assert.equal(bb.size(), 1);
  bb.clear();
  assert.equal(bb.size(), 0);
});
