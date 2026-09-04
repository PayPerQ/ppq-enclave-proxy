// The point of key_sources is to make one specific silent failure visible: a
// KMS decrypt that failed, was covered by the plaintext fallback, and left
// everything working while the attestation gating did nothing. So the tests
// care most about that value being distinguishable, and about never leaking
// anything derived from a secret.

import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { KEY_SOURCE_VALUES, isDegradedSource, keySources } from '../src/keySources.mjs';

const BOOT_SH = fileURLToPath(new URL('../boot.sh', import.meta.url));

test('reports the marker boot.sh exported, per secret', () => {
  const s = keySources({
    OPENROUTER_KEY_SOURCE: 'kms',
    FIREWORKS_KEY_SOURCE: 'absent',
    ANTHROPIC_KEY_SOURCE: 'init-plaintext',
    VERTEX_KEY_SOURCE: 'init-plaintext-after-kms-failure',
  });
  assert.deepEqual(s, {
    openrouter: 'kms',
    fireworks: 'absent',
    anthropic: 'init-plaintext',
    vertex: 'init-plaintext-after-kms-failure',
  });
});

test('an unset marker is `unknown`, never `absent`', () => {
  // A boot.sh predating this instrumentation is a different situation from a
  // key that was not supplied. Reporting `absent` would be a false all-clear on
  // precisely the question this endpoint exists to answer.
  assert.deepEqual(keySources({}), {
    openrouter: 'unknown',
    fireworks: 'unknown',
    anthropic: 'unknown',
    vertex: 'unknown',
  });
  assert.equal(keySources({ OPENROUTER_KEY_SOURCE: '' }).openrouter, 'unknown');
});

test('an unexpected value is flagged rather than passed through', () => {
  assert.equal(keySources({ OPENROUTER_KEY_SOURCE: 'sk-live-abc' }).openrouter, 'unrecognized');
});

test('degradedness treats `absent` as fine and everything non-kms as not', () => {
  assert.equal(isDegradedSource('kms'), false);
  // A provider that is not configured cannot be ungated.
  assert.equal(isDegradedSource('absent'), false);
  for (const v of ['init-plaintext', 'init-plaintext-after-kms-failure', 'kms-failed', 'unknown']) {
    assert.equal(isDegradedSource(v), true, `${v} should count as degraded`);
  }
});

test('the failed-then-fell-back case is distinguishable from a plain fallback', () => {
  // Collapsing these two would hide the silent failure this whole mechanism
  // exists to expose: gating that does nothing while everything looks healthy.
  assert.notEqual(
    keySources({ OPENROUTER_KEY_SOURCE: 'init-plaintext-after-kms-failure' }).openrouter,
    keySources({ OPENROUTER_KEY_SOURCE: 'init-plaintext' }).openrouter,
  );
});

test('carries nothing derived from a secret', () => {
  // The endpoint is public and unauthenticated. A length would be a
  // distinguisher; the branch name is not.
  const values = Object.values(keySources({
    OPENROUTER_KEY_SOURCE: 'kms',
    FIREWORKS_KEY_SOURCE: 'init-plaintext',
    ANTHROPIC_KEY_SOURCE: 'kms-failed',
    VERTEX_KEY_SOURCE: 'absent',
  }));
  for (const v of values) {
    assert.ok(
      KEY_SOURCE_VALUES.includes(v),
      `${v} is not one of the fixed branch names — a value derived from a secret could leak here`,
    );
  }
});

// ── boot.sh's own logic ──────────────────────────────────────────────────────
//
// The JS above only formats what boot.sh decided. The decision is the part that
// can actually be wrong, and it is written in shell under `set -eu`, so it is
// worth executing rather than reasoning about. These run the real branch
// structure with kmstool stubbed, which is the only way to reach the KMS paths
// off a Nitro host.

function runBootFragment({ ciphertext, plaintext, kmsSucceeds }) {
  const dir = mkdtempSync(join(tmpdir(), 'bootsrc-'));
  const stub = join(dir, 'kmstool_enclave_cli');
  writeFileSync(
    stub,
    kmsSucceeds
      ? '#!/bin/sh\necho "PLAINTEXT: $(printf secret | base64)"\n'
      : '#!/bin/sh\necho "boom" >&2\nexit 1\n',
    { mode: 0o755 },
  );

  // Lift the real fragment out of boot.sh rather than restating it — a copy
  // would drift and then pass while production behaved differently.
  const boot = readFileSync(BOOT_SH, 'utf8');
  const start = boot.indexOf('fallback_source()');
  const end = boot.indexOf('# Fireworks direct key');
  assert.ok(start > 0 && end > start, 'could not locate the OpenRouter delivery block in boot.sh');
  const fragment = boot.slice(start, end);

  const script = [
    'set -eu',
    'log() { :; }',
    `PATH="${dir}:$PATH"`,
    'REGION=us-east-1 KMS_VSOCK_PORT=8000',
    'AWS_ACCESS_KEY_ID=a AWS_SECRET_ACCESS_KEY=b AWS_SESSION_TOKEN=c',
    `KEY_CIPHERTEXT='${ciphertext}'`,
    `KEY_PLAINTEXT='${plaintext}'`,
    fragment,
    'echo "$OPENROUTER_KEY_SOURCE"',
  ].join('\n');

  const path = join(dir, 'frag.sh');
  writeFileSync(path, script);
  return execFileSync('sh', [path], { encoding: 'utf8' }).trim();
}

test('boot.sh: ciphertext + working kmstool reports kms', () => {
  assert.equal(runBootFragment({ ciphertext: 'ct', plaintext: 'pt', kmsSucceeds: true }), 'kms');
});

test('boot.sh: no ciphertext reports init-plaintext', () => {
  assert.equal(runBootFragment({ ciphertext: '', plaintext: 'pt', kmsSucceeds: true }), 'init-plaintext');
});

test('boot.sh: failed decrypt covered by fallback is NOT reported as init-plaintext', () => {
  // The regression that matters. Before this instrumentation, this case and the
  // one above were the same observable state.
  assert.equal(
    runBootFragment({ ciphertext: 'ct', plaintext: 'pt', kmsSucceeds: false }),
    'init-plaintext-after-kms-failure',
  );
});

test('boot.sh: failed decrypt with no fallback reports kms-failed', () => {
  assert.equal(runBootFragment({ ciphertext: 'ct', plaintext: '', kmsSucceeds: false }), 'kms-failed');
});

test('boot.sh: nothing supplied reports absent', () => {
  assert.equal(runBootFragment({ ciphertext: '', plaintext: '', kmsSucceeds: true }), 'absent');
});
