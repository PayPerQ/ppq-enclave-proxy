// Pure helpers for the Azure standby's certificate (renew-azure-cert-dns01.mjs
// and check-azure-standby-cert.mjs). Everything that can be unit-tested
// without the network or `az` lives here; see enclave/test/azureCert.test.mjs.
import tls from 'node:tls';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';

export const AZURE_RESOURCE_GROUP = 'ppq-backend';
export const AZURE_APP = 'ppq-backend-us';
export const AZURE_APP_HOST = 'ppq-backend-us.azurewebsites.net';
export const DEFAULT_DOMAIN = 'api.ppq.ai';

/**
 * Days left on a certificate given its `valid_to` / `validTo` string as node
 * prints it ("Jan 22 23:59:59 2027 GMT") or any ISO date. NaN when unparsable.
 */
export function daysLeft(validTo, now = Date.now()) {
  const t = Date.parse(validTo);
  return Number.isFinite(t) ? (t - now) / 86_400_000 : NaN;
}

/**
 * Renew when forced, when the remaining time is unknown (unreadable served
 * certificate: the same rule the enclave renewal applies), or when at or
 * under `minDays`.
 */
export function renewalDecision({ daysLeft: d, minDays, force = false }) {
  if (force) return { renew: true, reason: 'forced' };
  if (!Number.isFinite(d)) return { renew: true, reason: 'served certificate could not be read' };
  if (d > minDays) return { renew: false, reason: `more than ${minDays} days left` };
  return { renew: true, reason: `${d.toFixed(1)} days left (<= ${minDays})` };
}

/** base64 SHA-256 over the SubjectPublicKeyInfo, the value `/health` and receipts print. */
export function spkiSha256(certOrKey) {
  const key = certOrKey instanceof X509Certificate ? certOrKey.publicKey : createPublicKey(certOrKey);
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64');
}

/** True when the leaf was issued for exactly this private key. */
export function publicKeyMatches(leaf, privateKey) {
  return spkiSha256(leaf) === spkiSha256(privateKey);
}

/** The DNS names a certificate covers (SAN, falling back to CN). */
export function certificateNames(cert) {
  const san = (cert.subjectAltName || '').split(',').map((s) => s.trim()).filter((s) => s.startsWith('DNS:')).map((s) => s.slice(4));
  if (san.length) return san;
  const cn = /CN=([^\n,]+)/.exec(cert.subject || '');
  return cn ? [cn[1]] : [];
}

/**
 * `openssl pkcs12 -export` arguments. The password is NOT in argv: openssl
 * reads it from the environment variable named by `passEnv` (`-passout
 * env:NAME`), so a process listing on the runner never shows it. The PBE
 * algorithms are pinned to the PKCS#12 profile every Windows host accepts
 * (OpenSSL 3's AES-256/PBKDF2 default has been rejected by App Service).
 */
export function pfxExportArgs({ keyPath, chainPath, outPath, name, passEnv = 'PFXPASS' }) {
  for (const [k, v] of Object.entries({ keyPath, chainPath, outPath, name })) if (!v) throw new Error(`pfxExportArgs: ${k} is required`);
  if (!/^[A-Z_][A-Z0-9_]*$/i.test(passEnv)) throw new Error('pfxExportArgs: passEnv must be an environment variable name');
  return ['pkcs12', '-export', '-inkey', keyPath, '-in', chainPath, '-out', outPath, '-name', name,
    '-passout', `env:${passEnv}`, '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1'];
}

/** Common `az webapp config ssl …` resource arguments. */
function azTarget({ resourceGroup = AZURE_RESOURCE_GROUP, app = AZURE_APP, subscription } = {}) {
  const out = ['--resource-group', resourceGroup, '--name', app];
  if (subscription) out.push('--subscription', subscription);
  return out;
}

/**
 * `az webapp config ssl upload` has no environment form for the PFX password,
 * so it is in argv for the seconds the call takes; the PFX itself is deleted
 * right after and the password is never printed.
 */
export function azUploadArgs({ pfxPath, password, certificateName, ...target }) {
  if (!pfxPath || !password) throw new Error('azUploadArgs: pfxPath and password are required');
  const out = ['webapp', 'config', 'ssl', 'upload', ...azTarget(target),
    '--certificate-file', pfxPath, '--certificate-password', password, '--output', 'json'];
  if (certificateName) out.push('--certificate-name', certificateName);
  return out;
}

/**
 * Bind by thumbprint AND hostname. `--hostname` is optional to `az` (it would
 * match the certificate's names against the app's), but naming it makes the
 * binding replaced deterministic: the api.ppq.ai hostname binding already
 * exists and this swaps its SNI thumbprint in place.
 */
export function azBindArgs({ thumbprint, hostname, ...target }) {
  if (!thumbprint || !hostname) throw new Error('azBindArgs: thumbprint and hostname are required');
  return ['webapp', 'config', 'ssl', 'bind', ...azTarget(target),
    '--certificate-thumbprint', thumbprint, '--ssl-type', 'SNI', '--hostname', hostname, '--output', 'json'];
}

export function azHostnameListArgs({ resourceGroup = AZURE_RESOURCE_GROUP, app = AZURE_APP, subscription } = {}) {
  const out = ['webapp', 'config', 'hostname', 'list', '--resource-group', resourceGroup, '--webapp-name', app, '--output', 'json'];
  if (subscription) out.push('--subscription', subscription);
  return out;
}

/** Thumbprint (upper-case hex SHA-1) from `az webapp config ssl upload` JSON output. */
export function parseThumbprint(jsonText) {
  let j;
  try { j = JSON.parse(jsonText); } catch { throw new Error('az ssl upload did not return JSON'); }
  const t = String(j?.thumbprint || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(t)) throw new Error('az ssl upload output has no thumbprint');
  return t;
}

/** The thumbprint the app has bound for `hostname`, from `az webapp config hostname list` JSON. */
export function boundThumbprint(jsonText, hostname) {
  let list;
  try { list = JSON.parse(jsonText); } catch { throw new Error('az hostname list did not return JSON'); }
  const entry = (Array.isArray(list) ? list : []).find((h) => String(h?.name || '').toLowerCase() === hostname.toLowerCase());
  if (!entry) return null;
  return { sslState: entry.sslState || null, thumbprint: entry.thumbprint ? String(entry.thumbprint).toUpperCase() : null };
}

/** SHA-1 thumbprint of a certificate the way Azure prints it (upper-case hex, no colons). */
export function thumbprintOf(cert) {
  return cert.fingerprint.replace(/:/g, '').toUpperCase();
}

/**
 * The certificate `host` serves for SNI `servername`, as an X509Certificate.
 * `rejectUnauthorized: false` on purpose: reading the served certificate is
 * the point even when it is expired or from an untrusted CA.
 */
export function servedCertificate({ host, servername, port = 443, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const raw = s.getPeerCertificate(false)?.raw;
      s.end();
      if (!raw) { reject(new Error(`${host} presented no certificate for ${servername}`)); return; }
      resolve(new X509Certificate(raw));
    });
    s.on('timeout', () => s.destroy(new Error(`TLS connect to ${host} timed out`)));
    s.on('error', reject);
  });
}

/** One line describing a served certificate; nothing secret in it. */
export function describeCertificate(cert, now = Date.now()) {
  const d = daysLeft(cert.validTo, now);
  return `notAfter=${new Date(cert.validTo).toISOString()} (${Number.isFinite(d) ? d.toFixed(1) : '?'} days) ` +
    `names=${certificateNames(cert).join(',')} issuer="${cert.issuer.replace(/\n/g, ' ')}" ` +
    `thumbprint=${thumbprintOf(cert)} spki_sha256=${spkiSha256(cert)}`;
}
