// #195: once an ACME certificate is installed, NO client may be served the boot
// self-signed certificate -- not a TLS 1.2 client, not one that prefers RSA,
// not one with an unknown SNI -- and the receipt signing key must be the key
// of whatever certificate a connection was served.
//
// The boot certificate here is deliberately RSA, the shape that was in
// production: with an EC boot key (boot.sh now) the bug cannot show, and a test
// that passes for that reason proves nothing about the code under test.
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { createServedIdentity, spkiSha256Hex } from '../src/servedIdentity.mjs';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
const skip = !haveOpenssl() && 'openssl not available';

function pem(dir, name, keyArgs, subj, san) {
  const key = join(dir, `${name}.key`); const cert = join(dir, `${name}.crt`);
  execFileSync('openssl', ['req', '-x509', ...keyArgs, '-nodes', '-days', '1', '-subj', subj, ...(san ? ['-addext', `subjectAltName=${san}`] : []),
    '-keyout', key, '-out', cert], { stdio: 'pipe' });
  return { key: readFileSync(key), cert: readFileSync(cert) };
}
const RSA = ['-newkey', 'rsa:2048'];
const EC = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'];

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

/** SPKI hex of the certificate a client is served, for the given client options. */
function servedSpki(port, opts) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ port, host: '127.0.0.1', rejectUnauthorized: false, ...opts }, () => {
      const raw = s.getPeerCertificate(false)?.raw;
      s.end();
      resolve(raw ? spkiSha256Hex(raw) : null);
    });
    s.on('error', reject);
  });
}

let dir, boot, issued, challenge, bootSpki, issuedSpki, challengeSpki;
test.before(() => {
  if (skip) return;
  dir = mkdtempSync(join(tmpdir(), 'served-identity-'));
  boot = pem(dir, 'boot', RSA, '/CN=ppq-enclave-proxy');
  issued = pem(dir, 'issued', EC, '/CN=enclave-direct.test', 'DNS:api.test,DNS:enclave-direct.test');
  challenge = pem(dir, 'challenge', EC, '/CN=api.test');
  bootSpki = spkiSha256Hex(boot.cert); issuedSpki = spkiSha256Hex(issued.cert); challengeSpki = spkiSha256Hex(challenge.cert);
  assert.notEqual(bootSpki, issuedSpki);
});
test.after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

/** A server shaped like server.mjs's: identity default + SNICallback for issued names and one challenge name. */
async function startServer(identity, { issuedNames = ['api.test', 'enclave-direct.test'], challengeName = 'chal.test' } = {}) {
  const served = []; // [spki the socket presented, key identity chose] per connection, as server.mjs sees them
  const server = https.createServer({
    ...identity.contextOptions(),
    SNICallback: (name, cb) => {
      if (name === challengeName) return cb(null, createSecureContext({ key: challenge.key, cert: challenge.cert }));
      if (issuedNames.includes(name)) return cb(null, createSecureContext({ key: issued.key, cert: issued.cert }));
      return cb(null, null);
    },
  }, (req, res) => res.end('ok'));
  server.on('secureConnection', (sock) => {
    const cert = sock.getCertificate();
    served.push({ spki: cert?.raw ? spkiSha256Hex(cert.raw) : null, key: identity.signingKeyFor(cert) });
  });
  identity.attach(server);
  const port = await freePort();
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return { server, port, served, close: () => new Promise((r) => server.close(r)) };
}

test('the reproduction: with the boot certificate as default, TLS 1.2 is served the boot certificate despite SNI', { skip }, async () => {
  // Not the behaviour we want -- it is the bug, pinned so the fix below is
  // shown to change something. An identity that has NOT adopted keeps the
  // boot pair as default, exactly the pre-fix server.
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  const { port, close } = await startServer(identity);
  try {
    assert.equal(await servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.3' }), issuedSpki, 'TLS 1.3 picks by sigalg: ECDSA first, the issued cert');
    assert.equal(await servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.2' }), bootSpki, 'TLS 1.2 picks by cipher family: RSA wins, the boot cert -- the #195 bug');
  } finally { await close(); }
});

test('after adopt, every client is served the issued certificate: TLS 1.2, RSA-preferring, unknown SNI, no SNI', { skip }, async () => {
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  const { port, close } = await startServer(identity);
  try {
    assert.equal(identity.adopt(issued), true);
    assert.equal(identity.isBoot(), false);
    assert.equal(identity.currentSpkiSha256(), issuedSpki);
    for (const [label, opts] of [
      ['TLS 1.2 + SNI', { servername: 'api.test', maxVersion: 'TLSv1.2' }],
      ['TLS 1.3 + SNI', { servername: 'api.test', maxVersion: 'TLSv1.3' }],
      ['TLS 1.2 + unknown SNI', { servername: 'nobody.test', maxVersion: 'TLSv1.2' }],
      ['TLS 1.2 + no SNI (bare IP)', { maxVersion: 'TLSv1.2' }],
      ['TLS 1.3 + no SNI (bare IP)', { maxVersion: 'TLSv1.3' }],
    ]) {
      assert.equal(await servedSpki(port, opts), issuedSpki, label);
    }
    // A client that can ONLY do RSA now fails the handshake instead of being
    // served an untrusted certificate. It would have failed validation before;
    // failing the handshake is the honest outcome, and never the boot cert.
    await assert.rejects(servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.3', sigalgs: 'rsa_pss_rsae_sha256' }));
    await assert.rejects(servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.2', ciphers: 'ECDHE-RSA-AES128-GCM-SHA256' }));
  } finally { await close(); }
});

test('adopt keeps SNICallback working: a challenge name is still answered with the challenge certificate', { skip }, async () => {
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  const { port, close } = await startServer(identity);
  try {
    identity.adopt(issued);
    assert.equal(await servedSpki(port, { servername: 'chal.test' }), challengeSpki, 'setSecureContext must not discard the server-level SNICallback');
    assert.equal(await servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.2' }), issuedSpki);
  } finally { await close(); }
});

test('the signing key is the key of the certificate the connection was served, by SPKI', { skip }, async () => {
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  const { port, served, close } = await startServer(identity);
  try {
    const bootKey = createPrivateKey(boot.key); const issuedKey = createPrivateKey(issued.key);
    await servedSpki(port, { servername: 'nobody.test', maxVersion: 'TLSv1.2' });
    assert.equal(served.at(-1).spki, bootSpki);
    assert.ok(served.at(-1).key.equals(bootKey), 'before adopt: boot cert served, boot key signs');
    identity.adopt(issued);
    await servedSpki(port, { servername: 'nobody.test', maxVersion: 'TLSv1.2' });
    assert.equal(served.at(-1).spki, issuedSpki);
    assert.ok(served.at(-1).key.equals(issuedKey), 'after adopt, unknown SNI: issued cert served, so the ISSUED key must sign -- a lookup by SNI would pick the boot key here (#112 shape)');
    await servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.3' });
    assert.ok(served.at(-1).key.equals(issuedKey));
    // A socket that cannot say what it served (a test double) gets the default's
    // key -- the same fallback connectionSpki makes -- never a foreign one.
    assert.ok(identity.signingKeyFor(undefined).equals(issuedKey));
    assert.ok(identity.signingKeyFor({ raw: Buffer.from('not a certificate') }).equals(issuedKey));
    // A certificate that WAS served but that this identity does not hold (the
    // challenge certificate lives in acmeRunner): no key, never a guess.
    assert.equal(identity.signingKeyFor({ raw: new X509Certificate(challenge.cert).raw }), null);
    assert.deepEqual(identity.currentSpki(), { hex: issuedSpki, b64: new X509Certificate(issued.cert).publicKey.export({ type: 'spki', format: 'der' }).toString('base64') });
  } finally { await close(); }
});

test('a rejected context commits nothing: boot stays current, the same credentials can be retried', { skip }, () => {
  // CodeRabbit on #196: committing `current` before setSecureContext meant a
  // rejected context left the identity signing with a key whose certificate
  // was not on the wire, and the idempotence check then refused the retry.
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  const bootKey = createPrivateKey(boot.key);
  const calls = [];
  identity.attach({ setSecureContext: (o) => { calls.push(o); throw new Error('rejected by openssl'); } });
  assert.throws(() => identity.adopt(issued), /rejected by openssl/);
  assert.equal(identity.isBoot(), true);
  assert.equal(identity.currentSpkiSha256(), bootSpki);
  assert.ok(identity.signingKeyFor(undefined).equals(bootKey), 'still signs with the boot key: that is what is on the wire');
  assert.equal(identity.signingKeyFor({ raw: new X509Certificate(issued.cert).raw }), null, 'the rejected key was not registered');
  identity.attach({ setSecureContext: (o) => calls.push(o) });
  assert.equal(identity.adopt(issued), true, 'retry with the same credentials is not treated as already-current');
  assert.equal(identity.isBoot(), false);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].minVersion, 'TLSv1.2');
});

test('adopt before attach: the server is created already serving the issued certificate (worker order)', { skip }, async () => {
  // Workers apply state.issued / MSG.ISSUED before https.createServer runs.
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  identity.adopt(issued);
  const { port, close } = await startServer(identity);
  try {
    assert.equal(await servedSpki(port, { servername: 'api.test', maxVersion: 'TLSv1.2' }), issuedSpki);
    assert.equal(await servedSpki(port, { maxVersion: 'TLSv1.2' }), issuedSpki);
  } finally { await close(); }
});

test('adopt is idempotent and refuses incomplete credentials', { skip }, () => {
  const identity = createServedIdentity({ key: boot.key, cert: boot.cert });
  assert.equal(identity.adopt(null), false);
  assert.equal(identity.adopt({ key: issued.key }), false);
  assert.equal(identity.isBoot(), true);
  assert.equal(identity.adopt(issued), true);
  assert.equal(identity.adopt(issued), false, 'same certificate again: no-op');
  assert.equal(identity.currentSpkiSha256(), issuedSpki);
  assert.throws(() => createServedIdentity({ key: boot.key }), /required/);
});
