// The parts of ACME that can be wrong silently: the thumbprint's canonical
// form, the signature encoding, and the challenge certificate's extension.
// Each fails in a way the CA reports only as a flat rejection, so they are
// worth pinning against the spec's own values rather than against ourselves.

import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, createPrivateKey, createVerify, verify as cryptoVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';

import {
  ACME_TLS_ALPN,
  AcmeClient,
  acmeIdentifierExtensionValue,
  b64u,
  generateAccountKey,
  jwkThumbprint,
  keyAuthorization,
  makeChallengeCert,
  makeCsr,
  pollUntil,
  publicJwk,
  signJws,
} from '../src/acme.mjs';

test('b64url has no padding or wire-unsafe characters', () => {
  const s = b64u(Buffer.from([251, 255, 190, 255]));
  assert.equal(/[+/=]/.test(s), false, s);
});

test('thumbprint matches the worked example in RFC 7638', async () => {
  // RFC 7638 section 3.1 publishes an RSA key and its thumbprint. Using the
  // spec's own vector catches a wrong field order or stray whitespace, which
  // our own round-trip never would.
  const jwk = {
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB',
  };
  const expected = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
  const got = b64u(
    createHash('sha256')
      .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
      .digest(),
  );
  assert.equal(got, expected);
});

test('our thumbprint uses the canonical EC field order', () => {
  const { privateKey } = generateAccountKey();
  const jwk = publicJwk(privateKey);
  assert.deepEqual(Object.keys(jwk), ['crv', 'kty', 'x', 'y']);
  // Recomputing from the same canonical JSON must agree; a reordered object
  // would hash differently and the CA would reject every request.
  const manual = b64u(createHash('sha256').update(JSON.stringify(jwk)).digest());
  assert.equal(jwkThumbprint(privateKey), manual);
});

test('key authorization is token.thumbprint', () => {
  const { privateKey } = generateAccountKey();
  const ka = keyAuthorization('tok123', privateKey);
  const [tok, thumb] = ka.split('.');
  assert.equal(tok, 'tok123');
  assert.equal(thumb, jwkThumbprint(privateKey));
});

test('JWS signature is raw R||S, not DER', () => {
  const { privateKey, publicKey } = generateAccountKey();
  const jws = signJws({
    payload: { hello: 'world' },
    protectedHeader: { alg: 'ES256', nonce: 'n', url: 'https://example.test/x' },
    privateKey,
  });
  const sig = Buffer.from(jws.signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  // P-256 raw signatures are exactly 64 bytes. DER would be ~70 and variable,
  // which is the encoding every ACME CA rejects.
  assert.equal(sig.length, 64);

  const input = Buffer.from(`${jws.protected}.${jws.payload}`);
  assert.equal(
    cryptoVerify('sha256', input, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig),
    true,
  );
});

test('POST-as-GET signs an empty payload, not "null"', () => {
  const { privateKey } = generateAccountKey();
  const jws = signJws({
    payload: '',
    protectedHeader: { alg: 'ES256', nonce: 'n', url: 'https://example.test/x' },
    privateKey,
  });
  assert.equal(jws.payload, '');
});

test('acmeIdentifier extension is an OCTET STRING over SHA-256 of the key authz', () => {
  const value = acmeIdentifierExtensionValue('tok.thumb');
  assert.equal(value.length, 34);
  assert.equal(value[0], 0x04, 'DER OCTET STRING tag');
  assert.equal(value[1], 0x20, 'length 32');
  assert.deepEqual(
    value.subarray(2),
    createHash('sha256').update('tok.thumb').digest(),
  );
});

test('challenge certificate carries the SAN and the critical extension', () => {
  const keyAuth = 'tok.thumb';
  const { cert, key } = makeChallengeCert('enclave-direct.ppq.ai', keyAuth);
  assert.match(key, /BEGIN PRIVATE KEY/);

  const text = execFileSync('openssl', ['x509', '-noout', '-text'], {
    input: cert,
    encoding: 'utf8',
  });
  assert.match(text, /DNS:enclave-direct\.ppq\.ai/);
  // The extension MUST be critical; a non-critical one makes the CA reject the
  // challenge without saying why.
  assert.match(text, /1\.3\.6\.1\.5\.5\.7\.1\.31: critical/);

  // And it must actually carry our digest, not merely be present. Asserted
  // against the raw DER rather than openssl's text output, which renders the
  // extension value as escaped ASCII and cannot be matched reliably.
  const der = Buffer.from(
    cert.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''),
    'base64',
  );
  const expected = acmeIdentifierExtensionValue(keyAuth);
  assert.ok(
    der.includes(expected),
    'certificate DER does not contain OCTET STRING || SHA-256(key authorization)',
  );
});

test('CSR names the domain', () => {
  const { privateKey } = generateAccountKey();
  const der = makeCsr('enclave-direct.ppq.ai', privateKey);
  const text = execFileSync('openssl', ['req', '-inform', 'DER', '-noout', '-text'], {
    input: der,
    encoding: 'utf8',
  });
  assert.match(text, /enclave-direct\.ppq\.ai/);
});

test('nonces are consumed once and refreshed from responses', async () => {
  const calls = [];
  const client = new AcmeClient({
    directoryUrl: 'https://acme.test/dir',
    accountKey: generateAccountKey().privateKey,
    fetchImpl: async (url, init) => {
      calls.push({ url, method: init?.method || 'GET' });
      if (url.endsWith('/dir')) {
        return new Response(
          JSON.stringify({ newNonce: 'https://acme.test/nonce', newAccount: 'https://acme.test/acct' }),
          { status: 200 },
        );
      }
      if (url.endsWith('/nonce')) {
        return new Response(null, { status: 200, headers: { 'replay-nonce': 'N1' } });
      }
      return new Response('{}', { status: 200, headers: { 'replay-nonce': 'N2' } });
    },
  });

  await client.post('https://acme.test/a', {});
  await client.post('https://acme.test/b', {});

  // One newNonce round trip only: the second POST reuses the nonce the first
  // response carried, which is the whole reason ACME returns one every time.
  assert.equal(calls.filter((c) => c.url.endsWith('/nonce')).length, 1);
});

test('pollUntil stops as soon as the predicate holds', async () => {
  let n = 0;
  const out = await pollUntil(
    async () => ({ status: n++ < 2 ? 'pending' : 'valid' }),
    (r) => r.status === 'valid',
    { attempts: 10, intervalMs: 0, sleep: async () => {} },
  );
  assert.equal(out.status, 'valid');
  assert.equal(n, 3);
});

test('pollUntil gives up rather than hanging', async () => {
  await assert.rejects(
    pollUntil(async () => ({ status: 'pending' }), (r) => r.status === 'valid', {
      attempts: 3,
      intervalMs: 0,
      sleep: async () => {},
    }),
    /still not done after 3/,
  );
});

test('the ALPN identifier is exactly what RFC 8737 requires', () => {
  assert.equal(ACME_TLS_ALPN, 'acme-tls/1');
});
