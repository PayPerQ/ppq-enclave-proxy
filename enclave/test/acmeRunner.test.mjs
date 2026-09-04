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
} from '../src/acmeRunner.mjs';
import { makeChallengeCert } from '../src/acme.mjs';

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
