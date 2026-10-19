// The horse-power destination is a measured allowlist, not a parent choice
// (Oct 17-19 security reports: Threepujia, roolzer). These tests pin the rule
// and the wiring: server.mjs must obtain BOTH horse-power hosts through the
// gate, and the host-side send-init.sh must refuse a name the enclave will
// refuse, so the failure is a fast one on the host and not a dark enclave.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { HP_HOSTS, isAllowedHpHost, normalizeHpHost, pinHpHost, testAllowedHpHosts } from '../src/hpHosts.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (f) => readFileSync(join(root, f), 'utf8');

test('the production backend and the dev backend are the only names', () => {
  assert.ok(HP_HOSTS.includes('backend.ppq.ai'));
  assert.equal(HP_HOSTS.length, 2);
  assert.ok(Object.isFrozen(HP_HOSTS));
  for (const h of HP_HOSTS) assert.equal(h, normalizeHpHost(h), `${h} is not in normalized form`);
});

test('exact production and dev names are allowed, case- and trailing-dot-insensitively', () => {
  assert.ok(isAllowedHpHost('backend.ppq.ai'));
  assert.ok(isAllowedHpHost('BACKEND.PPQ.AI'));
  assert.ok(isAllowedHpHost('backend.ppq.ai.'));
  assert.ok(isAllowedHpHost(' backend.ppq.ai '));
  assert.ok(isAllowedHpHost(HP_HOSTS[1]));
  assert.deepEqual(pinHpHost('Backend.PPQ.ai.'), { host: 'backend.ppq.ai', status: 'pinned' });
});

test('names the parent could hold a certificate for are refused', () => {
  // The rollback arm's certbot certificate names enclave.ppq.ai (README known
  // gap 3); api.ppq.ai is the enclave's own name. Neither is horse-power.
  for (const h of [
    'enclave.ppq.ai',
    'api.ppq.ai',
    'enclave-dev.ppq.ai',
    'ppq.ai',
    'evil-backend.ppq.ai',
    'backend.ppq.ai.evil.example',
    'backend.ppq.ai:443',
    'https://backend.ppq.ai',
    'abc123.ngrok-free.dev',
    'ppq-backend-dev.azurewebsites.net',
    'ppq-backend-dev-a6fkdvbbbmg3dga3.scm.canadacentral-01.azurewebsites.net',
    'localhost',
    '127.0.0.1',
    'backend.ppq.ai\u0000',
  ]) {
    assert.equal(isAllowedHpHost(h, { allow: [] }), false, `${JSON.stringify(h)} must be refused`);
  }
});

test('pinHpHost fails closed: a refused name yields no host, and is reported', () => {
  const r = pinHpHost('evil.example', { allow: [] });
  assert.equal(r.host, '');
  assert.equal(r.status, 'rejected');
  assert.equal(r.rejected, 'evil.example');
  // Parent text is bounded before it reaches a log line or /health.
  assert.equal(pinHpHost('x'.repeat(5000), { allow: [] }).rejected.length, 253);
});

test('pinHpHost: unset stays unset (a dark arm is not a rejection)', () => {
  assert.deepEqual(pinHpHost(undefined), { host: '', status: 'unset' });
  assert.deepEqual(pinHpHost(''), { host: '', status: 'unset' });
  assert.deepEqual(pinHpHost('   '), { host: '', status: 'unset' });
});

test('non-strings are never a hostname', () => {
  for (const v of [null, 42, {}, [], true]) assert.equal(isAllowedHpHost(v), false);
  assert.equal(pinHpHost(null).status, 'unset');
  assert.equal(pinHpHost(42, { allow: [] }).status, 'rejected');
});

test('HP_HOST_ALLOW widens the list for tests only, and boot.sh can never set it', () => {
  assert.deepEqual(testAllowedHpHosts({}), []);
  assert.deepEqual(testAllowedHpHosts({ HP_HOST_ALLOW: 'localhost, Fake.Test.' }), ['localhost', 'fake.test']);
  assert.equal(isAllowedHpHost('localhost', { allow: ['localhost'] }), true);
  assert.equal(isAllowedHpHost('localhost', { allow: [] }), false);
  assert.deepEqual(pinHpHost('localhost', { allow: ['localhost'] }), { host: 'localhost', status: 'pinned' });
  // The parent's only way into the enclave environment is boot.sh's fixed set
  // of exports from the init blob. This name must never be one of them.
  const boot = read('enclave/boot.sh');
  assert.doesNotMatch(boot, /HP_HOST_ALLOW/);
  assert.doesNotMatch(read('scripts/send-init.sh'), /HP_HOST_ALLOW/);
});

test('server.mjs reads both horse-power hosts through the gate, and nothing else reads them raw', () => {
  const src = read('enclave/src/server.mjs');
  assert.match(src, /settleHost:\s*hpSettleHost\.host/, 'cfg.settleHost must come from pinHpHost');
  assert.match(src, /passthroughHost:\s*hpPassthroughHost\.host/, 'cfg.passthroughHost must come from pinHpHost');
  assert.match(src, /pinHpHost\(process\.env\.SETTLE_HOST\)/);
  assert.match(src, /pinHpHost\(process\.env\.PASSTHROUGH_HOST\)/);
  // The only reads of the raw env are the two gated ones.
  assert.equal((src.match(/process\.env\.SETTLE_HOST/g) || []).length, 1);
  assert.equal((src.match(/process\.env\.PASSTHROUGH_HOST/g) || []).length, 1);
  // And /health says what happened to them.
  assert.match(src, /hp_hosts:/);
});

test('send-init.sh refuses a settle_host / passthrough_host the enclave would refuse', () => {
  const sh = read('scripts/send-init.sh');
  assert.match(sh, /hpHosts\.mjs/, 'send-init.sh must consult the measured list');
  assert.match(sh, /not in enclave\/src\/hpHosts\.mjs/);
});
