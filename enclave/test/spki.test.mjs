import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { spkiSha256Hex, normalizePin, createKeyAcceptor } from '../../scripts/lib/spki.mjs';

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

test('createKeyAcceptor: the pin alone until a certificate is installed, then that certificate\'s key too, never anything else', () => {
  const dir = mkdtempSync(join(tmpdir(), 'spki-'));
  try {
    for (const n of ['boot', 'issued', 'other']) {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', `/CN=${n}`, '-keyout', join(dir, `${n}.key`), '-out', join(dir, `${n}.pem`)], { stdio: 'pipe' });
    }
    const raw = (n) => new X509Certificate(readFileSync(join(dir, `${n}.pem`))).raw;
    const boot = spkiSha256Hex(raw('boot')); const issued = spkiSha256Hex(raw('issued')); const other = spkiSha256Hex(raw('other'));
    const off = createKeyAcceptor('');
    assert.equal(off.enabled, false);
    const k = createKeyAcceptor(boot.toUpperCase());
    assert.equal(k.enabled, true);
    assert.equal(k.accepts(boot), true, 'the boot key (the pin) is accepted');
    assert.equal(k.accepts(issued), false, 'the not-yet-installed key is refused');
    assert.equal(k.accepts(other), false);
    assert.equal(k.accepts(null), false);
    k.addInstalled(raw('issued'));
    assert.equal(k.accepts(issued), true, 'after /acme/install the installed certificate\'s key is accepted');
    assert.equal(k.accepts(boot), true, 'the pin still is (workers may not have switched yet)');
    assert.equal(k.accepts(other), false, 'anything else is still refused');
    assert.deepEqual(k.list(), [boot, issued]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
