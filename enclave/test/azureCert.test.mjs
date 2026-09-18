// scripts/lib/azureCert.mjs: the pure parts of the Azure standby's certificate
// renewal and check -- days left, the skip decision, the openssl/az argument
// builders (PFX password via the environment, never argv), az output parsing,
// key/certificate matching, and reading a served certificate over TLS.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import {
  AZURE_APP, AZURE_RESOURCE_GROUP,
  azBindArgs, azHostnameListArgs, azUploadArgs, boundThumbprint, certificateNames, daysLeft, describeCertificate,
  leafValidityProblem, parseThumbprint, pfxExportArgs, publicKeyMatches, renewalDecision, servedCertificate, spkiSha256, thumbprintOf,
} from '../../scripts/lib/azureCert.mjs';

const DAY = 86_400_000;

/** A throwaway CA and a leaf for `name` over `privateKey` (openssl, like the other acme tests). */
function issue(name, privateKey) {
  const dir = mkdtempSync(join(tmpdir(), 'azcert-test-'));
  try {
    writeFileSync(join(dir, 'key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2',
      '-subj', '/CN=test-ca', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.pem')], { stdio: 'pipe' });
    execFileSync('openssl', ['req', '-new', '-key', join(dir, 'key.pem'), '-subj', `/CN=${name}`, '-out', join(dir, 'csr.pem')], { stdio: 'pipe' });
    writeFileSync(join(dir, 'ext.cnf'), `subjectAltName = DNS:${name}\nextendedKeyUsage = serverAuth\nbasicConstraints = CA:FALSE\n`);
    execFileSync('openssl', ['x509', '-req', '-in', join(dir, 'csr.pem'), '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca.key'),
      '-CAcreateserial', '-days', '2', '-extfile', join(dir, 'ext.cnf'), '-out', join(dir, 'leaf.pem')], { stdio: 'pipe' });
    return { leaf: readFileSync(join(dir, 'leaf.pem'), 'utf8'), ca: readFileSync(join(dir, 'ca.pem'), 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('daysLeft: node\'s valid_to format and ISO; NaN for garbage', () => {
  const now = Date.parse('2026-09-17T00:00:00Z');
  assert.equal(daysLeft('Jan 22 23:59:59 2027 GMT', now).toFixed(2), '128.00'); // 127 days + 23:59:59
  assert.equal(daysLeft('2026-10-17T00:00:00Z', now), 30);
  assert.ok(daysLeft('2026-09-16T00:00:00Z', now) < 0);
  assert.ok(Number.isNaN(daysLeft('not a date', now)));
  assert.ok(Number.isNaN(daysLeft(undefined, now)));
});

test('renewalDecision: skip above min-days; renew at or under, when forced, or when unreadable', () => {
  assert.equal(renewalDecision({ daysLeft: 126.8, minDays: 30 }).renew, false);
  assert.equal(renewalDecision({ daysLeft: 30.01, minDays: 30 }).renew, false);
  assert.equal(renewalDecision({ daysLeft: 30, minDays: 30 }).renew, true);
  assert.equal(renewalDecision({ daysLeft: 3, minDays: 30 }).renew, true);
  assert.equal(renewalDecision({ daysLeft: -1, minDays: 30 }).renew, true);
  assert.deepEqual(renewalDecision({ daysLeft: 126.8, minDays: 30, force: true }), { renew: true, reason: 'forced' });
  assert.equal(renewalDecision({ daysLeft: NaN, minDays: 30 }).renew, true);
  assert.match(renewalDecision({ daysLeft: 126.8, minDays: 30 }).reason, /more than 30 days/);
  // Plenty of lifetime but not one a client accepts for the name: renew.
  const bad = renewalDecision({ daysLeft: 126.8, minDays: 30, authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  assert.equal(bad.renew, true);
  assert.match(bad.reason, /not valid for the name \(ERR_TLS_CERT_ALTNAME_INVALID\)/);
  assert.equal(renewalDecision({ daysLeft: 126.8, minDays: 30, authorized: true }).renew, false);
});

test('leafValidityProblem: null inside the validity period; names the side it falls outside', () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { leaf } = issue('api.ppq.ai', key.privateKey);
  const cert = new X509Certificate(leaf);
  const from = Date.parse(cert.validFrom); const to = Date.parse(cert.validTo);
  assert.equal(leafValidityProblem(cert, from + 1000), null);
  assert.match(leafValidityProblem(cert, from - 60_000), /^not valid before /);
  assert.match(leafValidityProblem(cert, to), /^expired at /);
  assert.match(leafValidityProblem({ validFrom: 'garbage', validTo: 'garbage' }, Date.now()), /could not be parsed/);
});

test('pfxExportArgs: password through the environment, never argv; fixed PBE profile', () => {
  const a = pfxExportArgs({ keyPath: '/t/key.pem', chainPath: '/t/chain.pem', outPath: '/t/cert.pfx', name: 'api.ppq.ai' });
  assert.deepEqual(a.slice(0, 2), ['pkcs12', '-export']);
  assert.equal(a[a.indexOf('-passout') + 1], 'env:PFXPASS');
  assert.ok(!a.some((x) => x.startsWith('pass:')));
  assert.equal(a[a.indexOf('-inkey') + 1], '/t/key.pem');
  assert.equal(a[a.indexOf('-in') + 1], '/t/chain.pem');
  assert.equal(a[a.indexOf('-out') + 1], '/t/cert.pfx');
  assert.equal(a[a.indexOf('-name') + 1], 'api.ppq.ai');
  assert.equal(pfxExportArgs({ keyPath: 'k', chainPath: 'c', outPath: 'o', name: 'n', passEnv: 'OTHER' }).at(-7), 'env:OTHER');
  assert.throws(() => pfxExportArgs({ keyPath: 'k', chainPath: 'c', outPath: 'o', name: 'n', passEnv: 'not valid' }), /environment variable name/);
  assert.throws(() => pfxExportArgs({ keyPath: 'k', chainPath: 'c', name: 'n' }), /outPath is required/);
});

test('pfxExportArgs: openssl builds a PFX from key + chain with the password read from the environment', () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { leaf, ca } = issue('api.ppq.ai', key.privateKey);
  const dir = mkdtempSync(join(tmpdir(), 'azcert-pfx-'));
  try {
    writeFileSync(join(dir, 'key.pem'), key.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(join(dir, 'chain.pem'), leaf + ca);
    const args = pfxExportArgs({ keyPath: join(dir, 'key.pem'), chainPath: join(dir, 'chain.pem'), outPath: join(dir, 'cert.pfx'), name: 'api.ppq.ai' });
    execFileSync('openssl', args, { stdio: 'pipe', env: { ...process.env, PFXPASS: 'one-run-secret' } });
    // Wrong password: unreadable. Right password: leaf AND issuer are inside.
    assert.throws(() => execFileSync('openssl', ['pkcs12', '-in', join(dir, 'cert.pfx'), '-nokeys', '-passin', 'env:PFXPASS'], { stdio: 'pipe', env: { ...process.env, PFXPASS: 'wrong' } }));
    const certs = execFileSync('openssl', ['pkcs12', '-in', join(dir, 'cert.pfx'), '-nokeys', '-passin', 'env:PFXPASS'], { stdio: 'pipe', env: { ...process.env, PFXPASS: 'one-run-secret' } }).toString();
    assert.equal((certs.match(/-----BEGIN CERTIFICATE-----/g) || []).length, 2);
    const keyOut = execFileSync('openssl', ['pkcs12', '-in', join(dir, 'cert.pfx'), '-nocerts', '-nodes', '-passin', 'env:PFXPASS'], { stdio: 'pipe', env: { ...process.env, PFXPASS: 'one-run-secret' } }).toString();
    assert.match(keyOut, /-----BEGIN PRIVATE KEY-----/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('az argument builders: upload carries the password (az has no env form), bind names the hostname and SNI', () => {
  const up = azUploadArgs({ pfxPath: '/t/cert.pfx', password: 'pw', certificateName: 'api.ppq.ai-le-2026-09-17' });
  assert.deepEqual(up.slice(0, 4), ['webapp', 'config', 'ssl', 'upload']);
  assert.equal(up[up.indexOf('--resource-group') + 1], AZURE_RESOURCE_GROUP);
  assert.equal(up[up.indexOf('--name') + 1], AZURE_APP);
  assert.equal(up[up.indexOf('--certificate-file') + 1], '/t/cert.pfx');
  assert.equal(up[up.indexOf('--certificate-password') + 1], 'pw');
  assert.equal(up[up.indexOf('--certificate-name') + 1], 'api.ppq.ai-le-2026-09-17');
  assert.ok(!up.includes('--subscription'));
  assert.throws(() => azUploadArgs({ pfxPath: '/t/cert.pfx' }), /password/);

  const bind = azBindArgs({ thumbprint: 'ABC', hostname: 'api.ppq.ai', subscription: 'sub-1', resourceGroup: 'rg', app: 'app' });
  assert.deepEqual(bind, ['webapp', 'config', 'ssl', 'bind', '--resource-group', 'rg', '--name', 'app', '--subscription', 'sub-1',
    '--certificate-thumbprint', 'ABC', '--ssl-type', 'SNI', '--hostname', 'api.ppq.ai', '--output', 'json']);
  assert.throws(() => azBindArgs({ thumbprint: 'ABC' }), /hostname/);

  const list = azHostnameListArgs({ subscription: 's' });
  assert.deepEqual(list, ['webapp', 'config', 'hostname', 'list', '--resource-group', AZURE_RESOURCE_GROUP, '--webapp-name', AZURE_APP, '--output', 'json', '--subscription', 's']);
});

test('parseThumbprint / boundThumbprint: az JSON in, normalised upper-case hex out', () => {
  assert.equal(parseThumbprint('{"name":"x","thumbprint":"5891d38924509a4fcd156b24efdad8fde7a6fbb9"}'), '5891D38924509A4FCD156B24EFDAD8FDE7A6FBB9');
  assert.throws(() => parseThumbprint('{"name":"x"}'), /no thumbprint/);
  assert.throws(() => parseThumbprint('WARNING: not json'), /did not return JSON/);
  const list = JSON.stringify([
    { name: 'ppq-backend-us.azurewebsites.net', sslState: null, thumbprint: null },
    { name: 'API.ppq.ai', sslState: 'SniEnabled', thumbprint: '5891d38924509a4fcd156b24efdad8fde7a6fbb9' },
  ]);
  assert.deepEqual(boundThumbprint(list, 'api.ppq.ai'), { sslState: 'SniEnabled', thumbprint: '5891D38924509A4FCD156B24EFDAD8FDE7A6FBB9' });
  assert.equal(boundThumbprint(list, 'other.ppq.ai'), null);
  assert.throws(() => boundThumbprint('nope', 'api.ppq.ai'), /did not return JSON/);
});

test('publicKeyMatches / spkiSha256 / certificateNames / thumbprintOf on a real leaf', () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { leaf } = issue('api.ppq.ai', key.privateKey);
  const cert = new X509Certificate(leaf);
  assert.equal(publicKeyMatches(cert, key.privateKey), true);
  assert.equal(publicKeyMatches(cert, other.privateKey), false);
  assert.equal(spkiSha256(cert), spkiSha256(key.privateKey));
  assert.match(spkiSha256(cert), /^[A-Za-z0-9+/]{43}=$/);
  assert.deepEqual(certificateNames(cert), ['api.ppq.ai']);
  assert.match(thumbprintOf(cert), /^[0-9A-F]{40}$/);
  const line = describeCertificate(cert);
  assert.match(line, /names=api\.ppq\.ai/);
  assert.match(line, /thumbprint=[0-9A-F]{40}/);
  assert.ok(!line.includes('PRIVATE'), 'nothing secret in the description');
});

test('servedCertificate: reads the leaf a server presents for the SNI name; a refused connection rejects', async () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { leaf, ca } = issue('api.ppq.ai', key.privateKey);
  const server = tls.createServer({ key: key.privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: leaf + ca }, (s) => s.end());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const served = await servedCertificate({ host: '127.0.0.1', port: server.address().port, servername: 'api.ppq.ai' });
    assert.equal(served.cert.fingerprint256, new X509Certificate(leaf).fingerprint256);
    assert.equal(publicKeyMatches(served.cert, key.privateKey), true);
    // The test CA is not in Node's trust store: the read succeeds, the verdict says why a client would refuse.
    assert.equal(served.authorized, false);
    assert.equal(typeof served.authorizationError, 'string');
    assert.notEqual(served.authorizationError, '');
  } finally {
    server.close();
  }
  const closed = await new Promise((r) => { const s = tls.createServer({}).listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
  await assert.rejects(servedCertificate({ host: '127.0.0.1', port: closed, servername: 'api.ppq.ai', timeoutMs: 2000 }));
});
