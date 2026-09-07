// The hooks that run on EVERY handshake. Getting them wrong does not fail the
// ACME order -- it breaks ordinary clients, which is far worse and much less
// obvious. So most of this is about what happens when NO challenge is pending.

import assert from 'node:assert/strict';
import test from 'node:test';
import { createSecureContext } from 'node:tls';

import {
  __setPendingChallenge,
  challengeCredentials,
  hasPendingChallenge,
  selectAlpn,
  issuedSigningKey,
  setIssuedCertificate,
} from '../src/acmeRunner.mjs';
import { makeChallengeCert } from '../src/acme.mjs';
import { X509Certificate, sign, verify } from 'node:crypto';

const DOMAIN = 'enclave-direct.ppq.ai';

test('no challenge pending: acme-tls/1 is never negotiated', () => {
  // The dangerous direction. Negotiating acme-tls/1 for an ordinary client
  // makes the enclave answer with a certificate that client cannot use.
  __setPendingChallenge(DOMAIN, null);
  assert.equal(
    selectAlpn({ servername: DOMAIN, protocols: ['acme-tls/1', 'http/1.1'] }),
    'http/1.1',
  );
});

test('challenge pending: acme-tls/1 wins, but only for that name', () => {
  __setPendingChallenge(DOMAIN, makeChallengeCert(DOMAIN, 'tok.thumb'));
  try {
    assert.equal(selectAlpn({ servername: DOMAIN, protocols: ['acme-tls/1'] }), 'acme-tls/1');
    // A challenge for one name must not change how another name is answered.
    assert.equal(
      selectAlpn({ servername: 'enclave.ppq.ai', protocols: ['acme-tls/1', 'http/1.1'] }),
      'http/1.1',
    );
  } finally {
    __setPendingChallenge(DOMAIN, null);
  }
});

test('an ordinary browser offering h2 and http/1.1 gets http/1.1', () => {
  // This server speaks HTTP/1.1 only. Returning h2 would negotiate a protocol
  // it cannot serve, which is a worse failure than not negotiating at all.
  assert.equal(selectAlpn({ servername: DOMAIN, protocols: ['h2', 'http/1.1'] }), 'http/1.1');
});

test('preserves the pre-hook behaviour for clients that send no ALPN', () => {
  // Before this hook existed Node negotiated no ALPN and clients proceeded over
  // HTTP/1.1. An empty or absent list must not start rejecting them... but
  // Node only invokes the callback when ALPN is present, so the meaningful
  // assertion is that a malformed list does not throw.
  assert.doesNotThrow(() => selectAlpn({ servername: DOMAIN, protocols: undefined }));
  assert.equal(selectAlpn({ servername: DOMAIN, protocols: [] }), undefined);
});

test('an h2-only client is rejected rather than mis-served', () => {
  // undefined = fatal no_application_protocol. Correct: this server cannot
  // serve h2, and such a client was already broken here.
  assert.equal(selectAlpn({ servername: DOMAIN, protocols: ['h2'] }), undefined);
});

test('challenge lookup is exact, not prefix or suffix', () => {
  __setPendingChallenge(DOMAIN, makeChallengeCert(DOMAIN, 'tok.thumb'));
  try {
    assert.equal(hasPendingChallenge(DOMAIN), true);
    assert.equal(hasPendingChallenge('evil-' + DOMAIN), false);
    assert.equal(hasPendingChallenge(DOMAIN + '.evil.com'), false);
    assert.equal(hasPendingChallenge(undefined), false);
    assert.equal(hasPendingChallenge(null), false);
  } finally {
    __setPendingChallenge(DOMAIN, null);
  }
});

test('the stored challenge credentials load as a real TLS context', () => {
  // A certificate that openssl produced but Node cannot load would fail the
  // handshake at validation time, when the CA is already connecting.
  const creds = makeChallengeCert(DOMAIN, 'tok.thumb');
  __setPendingChallenge(DOMAIN, creds);
  try {
    const got = challengeCredentials(DOMAIN);
    assert.ok(got.key && got.cert);
    assert.doesNotThrow(() => createSecureContext({ key: got.key, cert: got.cert }));
  } finally {
    __setPendingChallenge(DOMAIN, null);
  }
});

test('defaults to the STAGING directory', async () => {
  // Production allows 5 duplicate certificates per week with no way to undo a
  // burn. An unproven client must not point there by default.
  const src = await import('node:fs').then((fs) =>
    fs.readFileSync(new URL('../src/acmeRunner.mjs', import.meta.url), 'utf8'),
  );
  assert.match(src, /directoryUrl\s*=\s*LETSENCRYPT_STAGING/);
});

// ── #112: the receipt signing key must match the attested certificate ────────
// The attestation commits to the SPKI of the certificate the peer actually saw.
// A receipt signed with any other key fails verification and reports a forgery
// that did not happen. These assert the CONTRACT, not the plumbing — both #83
// bugs were missed by tests that stubbed the layer under test.

test('issuedSigningKey returns the key that matches the served certificate', () => {
  const name = 'signing.example';
  const creds = makeChallengeCert(name, 'key-authorization');
  setIssuedCertificate(name, creds);

  const signingKey = issuedSigningKey(name);
  assert.ok(signingKey, 'no signing key for a name with an issued certificate');

  // The invariant, proven rather than asserted by inspection: something signed
  // with this key verifies against the PUBLIC key inside the served cert.
  const payload = Buffer.from('routing-receipt-payload');
  const sig = sign('sha256', payload, signingKey);
  const certPublicKey = new X509Certificate(creds.cert).publicKey;
  assert.equal(verify('sha256', payload, certPublicKey, sig), true);

  setIssuedCertificate(name, undefined);
});

test('issuedSigningKey is null when the name has no issued certificate', () => {
  // The boot-key fallback case, which is correct only because the attestation
  // will have committed to the boot certificate for that same connection.
  assert.equal(issuedSigningKey('never-issued.example'), null);
  assert.equal(issuedSigningKey(undefined), null);
  assert.equal(issuedSigningKey(''), null);
});

test('a renewal changes the signing key rather than reusing the old one', () => {
  const name = 'renewal.example';
  const first = makeChallengeCert(name, 'first');
  const second = makeChallengeCert(name, 'second');

  setIssuedCertificate(name, first);
  const k1 = issuedSigningKey(name);
  setIssuedCertificate(name, second);
  const k2 = issuedSigningKey(name);

  // Caching is keyed by the PEM, so a new certificate must yield a new key.
  const payload = Buffer.from('after-renewal');
  assert.equal(
    verify('sha256', payload, new X509Certificate(second.cert).publicKey,
      sign('sha256', payload, k2)),
    true,
  );
  assert.notEqual(k1, k2);
});
