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
  issuedCertificateSummary,
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

// ── /health must show what is actually SERVED ───────────────────────────────
// acme_store:"ok" means sealing works, not that the right certificate is
// installed. On 2026-09-07 a flip to LE production placed no order, the enclave
// kept serving STAGING, and every signal reported success. Only a hand-run TLS
// connection revealed it.

test('issuedCertificateSummary reports the issuer and flags staging', () => {
  const name = 'summary.example';
  setIssuedCertificate(name, makeChallengeCert(name, 'auth'));
  const summary = issuedCertificateSummary();
  assert.ok(summary[name], 'no entry for an installed certificate');
  assert.equal(typeof summary[name].issuer, 'string');
  assert.equal(typeof summary[name].not_after, 'string');
  // The self-signed challenge cert is not from Let's Encrypt staging, so the
  // flag must be false — it keys on the issuer, not on "is it self-signed".
  assert.equal(summary[name].staging, false);
});

test('issuedCertificateSummary skips names with no certificate', () => {
  setIssuedCertificate('empty.example', undefined);
  assert.equal(issuedCertificateSummary()['empty.example'], undefined);
});

test('an unparsable certificate is reported, not thrown', () => {
  // /health must never fail because a stored certificate is malformed.
  setIssuedCertificate('bad.example', { key: 'k', cert: 'not-a-certificate' });
  assert.equal(issuedCertificateSummary()['bad.example'].issuer, 'unparsable');
});

// ── #52 scaling: the cluster hooks around the challenge ──────────────────────
// Drive a whole order against a fake CA. The property: `onChallengeArmed` is
// AWAITED after the challenge is installed and BEFORE the CA is told to
// validate, and `onChallengeCleared` runs after validation whatever happened.
// A worker that has not been handed the challenge certificate fails the
// validating handshake, so the order must not proceed until every one has.
import { obtainCertificate, setPendingChallenge } from '../src/acmeRunner.mjs';

function fakeCa({ onAccept }) {
  const base = 'https://ca.test';
  let authzStatus = 'pending';
  const R = (body, { status = 200, headers = {} } = {}) =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json', 'replay-nonce': `n-${Math.random()}`, ...headers },
    });
  return async (url) => {
    const p = new URL(url).pathname;
    if (p === '/dir') return R({ newNonce: `${base}/nonce`, newAccount: `${base}/acct`, newOrder: `${base}/order` });
    if (p === '/nonce') return R('');
    if (p === '/acct') return R({ status: 'valid' }, { status: 201, headers: { location: `${base}/acct/1` } });
    if (p === '/order') return R({ status: 'pending', authorizations: [`${base}/authz/1`], finalize: `${base}/finalize` }, { status: 201, headers: { location: `${base}/order/1` } });
    if (p === '/authz/1') return R({ status: authzStatus, identifier: { type: 'dns', value: 'x.test' }, challenges: [{ type: 'tls-alpn-01', url: `${base}/chal/1`, token: 'tok' }] });
    if (p === '/chal/1') { onAccept(); authzStatus = 'valid'; return R({ status: 'processing' }); }
    if (p === '/finalize') return R({ status: 'valid' });
    if (p === '/order/1') return R({ status: 'valid', certificate: `${base}/cert/1` });
    if (p === '/cert/1') return R('-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n');
    return R({ error: `unknown ${p}` }, { status: 404 });
  };
}

test('cluster hooks: armed is awaited before the CA validates; cleared runs after', async () => {
  const events = [];
  const fetchImpl = fakeCa({
    onAccept: () => {
      events.push(`accept(pending=${hasPendingChallenge('x.test')})`);
    },
  });
  const result = await obtainCertificate({
    domains: ['x.test'],
    directoryUrl: 'https://ca.test/dir',
    fetchImpl,
    onChallengeArmed: async (name, creds) => {
      // Simulate the IPC round trip: the order must not continue until this resolves.
      await new Promise((r) => setTimeout(r, 20));
      assert.match(creds.key, /BEGIN .*PRIVATE KEY/);
      assert.match(creds.cert, /BEGIN CERTIFICATE/);
      events.push(`armed:${name}`);
    },
    onChallengeCleared: async (name) => {
      events.push(`cleared:${name}(pending=${hasPendingChallenge('x.test')})`);
    },
  });
  assert.deepEqual(events, ['armed:x.test', 'accept(pending=true)', 'cleared:x.test(pending=false)']);
  assert.deepEqual(result.domains, ['x.test']);
  assert.match(result.key, /BEGIN .*PRIVATE KEY/);
});

test('cluster hooks: a worker that cannot take the challenge fails the order and still disarms', async () => {
  const events = [];
  const fetchImpl = fakeCa({ onAccept: () => events.push('accept') });
  await assert.rejects(
    () => obtainCertificate({
      domains: ['x.test'], directoryUrl: 'https://ca.test/dir', fetchImpl,
      onChallengeArmed: async () => { throw new Error('worker 3 did not acknowledge'); },
      onChallengeCleared: async (name) => events.push(`cleared:${name}`),
    }),
    /worker 3 did not acknowledge/,
  );
  assert.deepEqual(events, ['cleared:x.test'], 'the CA was never told to validate, and the challenge was disarmed');
  assert.equal(hasPendingChallenge('x.test'), false);
});

test('setPendingChallenge is the real setter workers use', () => {
  setPendingChallenge('w.test', { key: 'k', cert: 'c' });
  assert.equal(hasPendingChallenge('w.test'), true);
  setPendingChallenge('w.test', null);
  assert.equal(hasPendingChallenge('w.test'), false);
});
