import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_WORKERS, MSG, isMessage, workerCount } from '../src/clusterProto.mjs';

test('workerCount: unset, empty, junk and <=1 all mean "no cluster"', () => {
  for (const v of [undefined, '', ' ', 'abc', '0', '1', '-3', 'NaN']) {
    assert.equal(workerCount({ ENCLAVE_WORKERS: v }), 1, JSON.stringify(v));
  }
  assert.equal(workerCount({}), 1);
});

test('workerCount: a real number is honoured and capped', () => {
  assert.equal(workerCount({ ENCLAVE_WORKERS: '6' }), 6);
  assert.equal(workerCount({ ENCLAVE_WORKERS: ' 12 ' }), 12);
  assert.equal(workerCount({ ENCLAVE_WORKERS: '999' }), MAX_WORKERS);
});

test('isMessage accepts only known message types', () => {
  for (const t of Object.values(MSG)) assert.ok(isMessage({ type: t }));
  for (const bad of [null, 'state', 42, {}, { type: 'shutdown' }]) assert.equal(isMessage(bad), false);
});
