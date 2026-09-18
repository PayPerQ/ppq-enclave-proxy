import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { spkiSha256Hex, normalizePin } from '../../scripts/lib/spki.mjs';

test('spkiSha256Hex: sha256 over the DER SPKI, lower-case hex, same as the attestation checker computes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'spki-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=t', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'pipe' });
    const x = new X509Certificate(readFileSync(join(dir, 'c.pem')));
    const want = createHash('sha256').update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    assert.equal(spkiSha256Hex(x.raw), want);
    assert.match(want, /^[0-9a-f]{64}$/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('normalizePin: hex in any case with separators; anything else refused', () => {
  const h = 'A'.repeat(64);
  assert.equal(normalizePin(h), 'a'.repeat(64));
  assert.equal(normalizePin(h.match(/../g).join(':')), 'a'.repeat(64));
  assert.throws(() => normalizePin('abc'), /64 hex/);
  assert.throws(() => normalizePin(`${h}!`), /only hex digits/);
  assert.throws(() => normalizePin(h.slice(0, 63) + 'g'), /only hex digits/);
  assert.throws(() => normalizePin(''), /64 hex/);
});
