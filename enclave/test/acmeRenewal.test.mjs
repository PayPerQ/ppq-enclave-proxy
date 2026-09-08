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
import { __resetRenewal, beginRenewalCsr, completeRenewal, hasPendingRenewal } from '../src/acmeRunner.mjs';

function signCsr(csrDerB64, sans) {
  const dir = mkdtempSync(join(tmpdir(), 'renew-test-'));
  try {
    writeFileSync(join(dir, 'csr.der'), Buffer.from(csrDerB64, 'base64'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2',
      '-subj', '/CN=test-ca', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.pem')], { stdio: 'pipe' });
    writeFileSync(join(dir, 'ext.cnf'), `subjectAltName = ${sans.map((s) => `DNS:${s}`).join(', ')}\n`);
    execFileSync('openssl', ['x509', '-req', '-in', join(dir, 'csr.der'), '-inform', 'DER', '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca.key'),
      '-CAcreateserial', '-days', '2', '-extfile', join(dir, 'ext.cnf'), '-out', join(dir, 'leaf.pem')], { stdio: 'pipe' });
    return readFileSync(join(dir, 'leaf.pem'), 'utf8') + readFileSync(join(dir, 'ca.pem'), 'utf8');
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
  const out = completeRenewal({ cert: chain });
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
  assert.throws(() => completeRenewal({ cert: chain }), /does not match the pending CSR key/);
  assert.ok(hasPendingRenewal(), 'still pending');
  void r;
});

test('completeRenewal: refuses a certificate missing one of the requested names', () => {
  __resetRenewal();
  const r = beginRenewalCsr({ domains: ['a.test', 'b.test'] });
  const chain = signCsr(r.csr_der_b64, ['a.test']);
  assert.throws(() => completeRenewal({ cert: chain }), /does not cover b\.test/);
});

test('completeRenewal: refuses with no pending CSR, and refuses non-PEM', () => {
  __resetRenewal();
  assert.throws(() => completeRenewal({ cert: 'x' }), /no renewal in progress/);
  beginRenewalCsr({ domains: ['a.test'] });
  assert.throws(() => completeRenewal({ cert: 'not a pem' }), /PEM/);
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
