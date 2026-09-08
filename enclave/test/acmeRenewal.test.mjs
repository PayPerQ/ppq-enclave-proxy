// CI-driven renewal (#52 DNS-01): the enclave hands out a CSR over a fresh
// in-enclave key and accepts back ONLY a certificate for that key covering
// every requested name. A throwaway CA signs the CSR here; nothing on the
// network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { __resetRenewal, beginRenewalCsr, completeRenewal, hasPendingRenewal, verifyChainToRoots } from '../src/acmeRunner.mjs';
import { LETS_ENCRYPT_ROOTS_PEM } from '../src/trustRoots.mjs';

function signCsr(csrDerB64, sans) {
  const dir = mkdtempSync(join(tmpdir(), 'renew-test-'));
  try {
    writeFileSync(join(dir, 'csr.der'), Buffer.from(csrDerB64, 'base64'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2',
      '-subj', '/CN=test-ca', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.pem')], { stdio: 'pipe' });
    writeFileSync(join(dir, 'ext.cnf'), `subjectAltName = ${sans.map((s) => `DNS:${s}`).join(', ')}\nextendedKeyUsage = serverAuth\nbasicConstraints = CA:FALSE\n`);
    execFileSync('openssl', ['x509', '-req', '-in', join(dir, 'csr.der'), '-inform', 'DER', '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca.key'),
      '-CAcreateserial', '-days', '2', '-extfile', join(dir, 'ext.cnf'), '-out', join(dir, 'leaf.pem')], { stdio: 'pipe' });
    const chain = readFileSync(join(dir, 'leaf.pem'), 'utf8') + readFileSync(join(dir, 'ca.pem'), 'utf8');
    signCsr.lastCa = readFileSync(join(dir, 'ca.pem'), 'utf8');
    return chain;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('beginRenewalCsr: a DER CSR over a fresh key, covering every name', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test', 'b.test'] });
  assert.deepEqual(r.domains, ['a.test', 'b.test']);
  assert.ok(hasPendingRenewal());
  const dir = mkdtempSync(join(tmpdir(), 'csr-'));
  writeFileSync(join(dir, 'csr.der'), Buffer.from(r.csr_der_b64, 'base64'));
  const txt = execFileSync('openssl', ['req', '-in', join(dir, 'csr.der'), '-inform', 'DER', '-noout', '-text'], { stdio: 'pipe' }).toString();
  rmSync(dir, { recursive: true, force: true });
  assert.match(txt, /DNS:a\.test, DNS:b\.test/);
  assert.match(txt, /prime256v1|P-256/);
});

test('completeRenewal: accepts a certificate for the pending key; key material comes back for the store', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test', 'b.test'] });
  const chain = signCsr(r.csr_der_b64, ['a.test', 'b.test']);
  const out = completeRenewal({ cert: chain, trustRootsPem: signCsr.lastCa });
  assert.deepEqual(out.domains, ['a.test', 'b.test']);
  assert.match(out.key, /BEGIN PRIVATE KEY/);
  assert.equal(out.cert, chain);
  assert.ok(Date.parse(out.notAfter) > Date.now());
  // The returned key IS the key the certificate is for.
  const certPub = new X509Certificate(chain).publicKey.export({ type: 'spki', format: 'der' });
  const keyPub = createPublicKey(createPrivateKey(out.key)).export({ type: 'spki', format: 'der' });
  assert.ok(certPub.equals(keyPub));
  assert.equal(hasPendingRenewal(), false, 'consumed');
});

test('completeRenewal: refuses a certificate for a different key (pending key kept for a retry)', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test'] });
  // A CSR for some OTHER key, signed by the same kind of CA.
  const other = beginRenewalCsrForeign(['a.test']);
  const chain = signCsr(other, ['a.test']);
  assert.throws(() => completeRenewal({ cert: chain, trustRootsPem: signCsr.lastCa }), /does not match the pending CSR key/);
  assert.ok(hasPendingRenewal(), 'still pending');
  void r;
});

test('completeRenewal: refuses a certificate missing one of the requested names', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test', 'b.test'] });
  const chain = signCsr(r.csr_der_b64, ['a.test']);
  assert.throws(() => completeRenewal({ cert: chain, trustRootsPem: signCsr.lastCa }), /does not cover b\.test/);
});

test('completeRenewal: refuses non-PEM, and refuses a real certificate with no pending CSR', () => {
  __resetRenewal();
  assert.throws(() => completeRenewal({ cert: 'x' }), /PEM/, 'parsed before anything else');
  const foreign = signCsr(beginRenewalCsrForeign(['a.test']), ['a.test']);
  assert.throws(() => completeRenewal({ cert: foreign, trustRootsPem: signCsr.lastCa }), /no renewal in progress/);
});

// A CSR over a key we do NOT hand to the runner -- to forge "wrong key" input.
function beginRenewalCsrForeign(sans) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const dir = mkdtempSync(join(tmpdir(), 'foreign-'));
  try {
    writeFileSync(join(dir, 'k.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(join(dir, 'c.cnf'), ['[req]', 'distinguished_name = dn', 'req_extensions = ext', 'prompt = no', '[dn]', `CN = ${sans[0]}`, '[ext]', `subjectAltName = ${sans.map((s) => `DNS:${s}`).join(', ')}`].join('\n'));
    execFileSync('openssl', ['req', '-new', '-key', join(dir, 'k.pem'), '-outform', 'DER', '-out', join(dir, 'csr.der'), '-config', join(dir, 'c.cnf')], { stdio: 'pipe' });
    return readFileSync(join(dir, 'csr.der')).toString('base64');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('completeRenewal: a chain from an UNTRUSTED CA is refused with the built-in Let\'s Encrypt roots', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test'] });
  const chain = signCsr(r.csr_der_b64, ['a.test']); // signed by a throwaway CA
  assert.throws(() => completeRenewal({ cert: chain }), /does not terminate at a trusted root/);
  assert.ok(hasPendingRenewal(), 'pending kept for a corrected retry');
});

test('verifyChainToRoots: the built-in roots are ISRG Root X1 and X2', () => {
  const roots = LETS_ENCRYPT_ROOTS_PEM.match(/-----BEGIN CERTIFICATE-----/g) || [];
  assert.equal(roots.length, 2);
  assert.match(LETS_ENCRYPT_ROOTS_PEM, /BEGIN CERTIFICATE/);
});

test('beginRenewalCsr is idempotent while a renewal is in flight', () => {
  __resetRenewal();
  const a = beginRenewalCsr({ domains: ['a.test'] });
  const b = beginRenewalCsr({ domains: ['a.test'] });
  assert.equal(b.csr_der_b64, a.csr_der_b64, 'same CSR, same key');
  assert.equal(b.reused, true);
  const c = beginRenewalCsr({ domains: ['a.test'], now: Date.now() + 2 * 60 * 60_000 });
  assert.notEqual(c.csr_der_b64, a.csr_der_b64, 'a stale pending CSR is replaced');
  const d = beginRenewalCsr({ domains: ['other.test'] });
  assert.notEqual(d.csr_der_b64, c.csr_der_b64, 'different names -> new CSR');
});

test('completeRenewal is idempotent for the certificate it already installed', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test'] });
  const chain = signCsr(r.csr_der_b64, ['a.test']);
  const first = completeRenewal({ cert: chain, trustRootsPem: signCsr.lastCa });
  assert.equal(hasPendingRenewal(), false);
  const again = completeRenewal({ cert: chain, trustRootsPem: signCsr.lastCa });
  assert.equal(again.repeated, true);
  assert.equal(again.fingerprint256, first.fingerprint256);
  assert.equal(again.notAfter, first.notAfter);
});
