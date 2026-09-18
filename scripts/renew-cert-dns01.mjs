#!/usr/bin/env node
// Renew the enclave's certificate from CI with DNS-01, the key staying in the
// enclave (#52 scaling).
//
// WHY
// ---
// Behind a load balancer the TLS-ALPN-01 validating handshake lands on a
// random box, so in-enclave renewal cannot work for a fleet. A DNS record is
// the same for every box. But the certificate's private key must never leave
// the enclave -- that is the property this whole project exists for -- so the
// split is:
//
//   enclave (renewal authority)   fresh key, CSR over it        POST /acme/csr
//   this script (CI)              proves the names with DNS-01, obtains the chain
//   enclave                       verifies chain is for ITS key, installs, seals,
//                                 saves (-> S3)                 POST /acme/install
//
// The GoDaddy token lives in CI, never in the enclave. The enclave routes are
// gated by ACME_CI_TOKEN (SSM /ppq-enclave/acme-ci-token).
//
// Usage:
//   ACME_CI_TOKEN=… GODADDY_API_TOKEN=… node scripts/renew-cert-dns01.mjs \
//     [--host enclave-direct.ppq.ai] [--directory prod|staging] [--min-days 30] [--force] [--no-install]
//     [--pin-spki <sha256 hex>]   accept the authority by its attested key instead of a CA chain (see below)
//
// `--directory staging` never installs (a staging chain is not browser
// trusted); it proves the CSR -> DNS-01 -> chain path end to end and checks
// the chain is for the enclave's key, then discards it.
import { argv, env, exit } from 'node:process';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { AcmeClient, LETSENCRYPT_PROD, LETSENCRYPT_STAGING, generateAccountKey } from '../enclave/src/acme.mjs';
// GoDaddy TXT placement, authoritative-nameserver wait, settle, order/retry:
// moved verbatim into scripts/lib/dns01.mjs so the Azure standby's renewal
// (renew-azure-cert-dns01.mjs) shares them. Behaviour here is unchanged.
import { createDns01 } from './lib/dns01.mjs';
import { spkiSha256Hex, normalizePin } from './lib/spki.mjs';

function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}
const HOST = arg('host', 'enclave-direct.ppq.ai');
const DIRECTORY = arg('directory', 'prod') === 'staging' ? LETSENCRYPT_STAGING : LETSENCRYPT_PROD;
const STAGING = DIRECTORY === LETSENCRYPT_STAGING;
const MIN_DAYS = Number(arg('min-days', '30'));
// GoDaddy's nameservers are anycast; the two addresses one resolver sees can
// be ahead of the edge the CA hits. Require every nameserver, then settle.
const DNS_SETTLE_S = Number(arg('dns-settle', '45'));
const ORDER_ATTEMPTS = 2;
const FORCE = argv.includes('--force');
// An enclave that holds NO certificate (a fresh sealed store, or a name set
// that its stored certificate does not cover) presents its boot self-signed
// certificate, which the default CA check refuses -- and then CI can never
// install the certificate that would end that state. `--pin-spki <sha256>`
// breaks the loop safely: the operator reads `cert_spki_sha256` from the
// authority's /attestation (committed in the Nitro-signed document, checked
// by scripts/check-live-attestation.mjs) and this client accepts exactly that
// key and nothing else, on every connection, before any header is sent.
const PIN = arg('pin-spki', '') ? normalizePin(arg('pin-spki', '')) : '';
const INSTALL = !argv.includes('--no-install') && !STAGING;
const ZONE = 'ppq.ai';
const CI_TOKEN = env.ACME_CI_TOKEN || '';
const GD_TOKEN = env.GODADDY_API_TOKEN || '';
const log = (m) => console.log(`[renew] ${m}`);

if (!CI_TOKEN) { console.error('ACME_CI_TOKEN is required'); exit(2); }
if (!GD_TOKEN) { console.error('GODADDY_API_TOKEN is required'); exit(2); }

// Talk to the authority box directly, with SNI for the hostname, and report
// the certificate it presented so a successful install is visible here.
function enclave(path, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: HOST, servername: HOST, path, method, agent: false, timeout: 60_000,
      // Pinned: the CA chain is not consulted at all; the key is what is
      // verified, at secureConnect below, and again on the response.
      rejectUnauthorized: !PIN, ...(PIN ? { checkServerIdentity: () => undefined } : {}),
      headers: { authorization: `Bearer ${CI_TOKEN}`, 'content-type': 'application/json', ...headers } }, (res) => {
      const raw = res.socket.getPeerCertificate(false)?.raw;
      if (PIN && (!raw || spkiSha256Hex(raw) !== PIN)) { req.destroy(new Error('authority key changed mid-request')); return; }
      const served = raw ? new X509Certificate(raw) : null;
      let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; });
      res.on('end', () => {
        let json = null; try { json = JSON.parse(b); } catch { /* not json */ }
        resolve({ status: res.statusCode, json, text: b, served });
      });
    });
    if (PIN) {
      req.on('socket', (s) => s.once('secureConnect', () => {
        const raw = s.getPeerCertificate(false)?.raw;
        const got = raw ? spkiSha256Hex(raw) : null;
        if (got !== PIN) req.destroy(new Error(`${HOST} presented key ${got || 'none'}; --pin-spki is ${PIN}. Refusing to talk to it.`));
      }));
    }
    req.on('timeout', () => req.destroy(new Error('enclave request timed out')));
    req.on('error', reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}

async function main() {
  // 0. Does it need renewing?
  const h = await enclave('/health', { headers: { authorization: '' } });
  if (h.status !== 200 || !h.json) throw new Error(`${HOST}/health -> ${h.status}`);
  const renewal = h.json.acme_renewal || {};
  if (renewal.mode !== 'dns01-ci' || !renewal.authority) {
    throw new Error(`${HOST} is not the dns01-ci renewal authority (acme_renewal=${JSON.stringify(renewal)})`);
  }
  const certInfo = h.json.acme_certificates?.[HOST];
  const daysLeft = certInfo?.not_after ? (Date.parse(certInfo.not_after) - Date.now()) / 86_400_000 : NaN;
  log(`${HOST}: served certificate expires ${certInfo?.not_after || 'unknown'} (${Number.isFinite(daysLeft) ? daysLeft.toFixed(1) : '?'} days)`);
  if (!FORCE && Number.isFinite(daysLeft) && daysLeft > MIN_DAYS) {
    log(`more than ${MIN_DAYS} days left; nothing to do (--force to renew anyway)`);
    return;
  }

  // 1. CSR from the enclave (fresh in-enclave key).
  const c = await enclave('/acme/csr', { method: 'POST' });
  if (c.status !== 200 || !c.json?.csr_der_b64) throw new Error(`/acme/csr -> ${c.status}: ${c.text}`);
  const csrDer = Buffer.from(c.json.csr_der_b64, 'base64');
  const names = c.json.domains;
  log(`CSR for ${names.join(', ')} (${csrDer.length} bytes DER)`);

  // 2. Order with DNS-01. The account key is per run: Let's Encrypt limits
  //    duplicate CERTIFICATES, not accounts. A DNS-class failure (the CA's
  //    resolver saw an edge that had not caught up) gets ONE fresh order with
  //    the records left in place; cleanup happens only at the very end.
  const accountKey = generateAccountKey().privateKey;
  const client = new AcmeClient({ directoryUrl: DIRECTORY, accountKey, fetchImpl: fetch });
  log(`registering against ${DIRECTORY}`);
  await client.register(env.ACME_EMAIL || undefined);
  const dns01 = createDns01({ zone: ZONE, godaddyToken: GD_TOKEN, log, settleSeconds: DNS_SETTLE_S, orderAttempts: ORDER_ATTEMPTS });
  const chain = await dns01.obtainCertificate({ client, accountKey, names, csrDer });
  const leaf = new X509Certificate(chain);
  log(`issued: subject=${leaf.subject.replace(/\n/g, ' ')} issuer=${leaf.issuer.replace(/\n/g, ' ')} notAfter=${new Date(leaf.validTo).toISOString()}`);

  // 3. Install (the enclave verifies the chain is for its pending key and covers every name).
  if (!INSTALL) {
    log(STAGING ? 'staging: chain obtained and verified against the CSR; NOT installed (by design)' : 'not installing (--no-install)');
    return;
  }
  const inst = await enclave('/acme/install', { method: 'POST', body: { cert: chain } });
  if (inst.status !== 200) throw new Error(`/acme/install -> ${inst.status}: ${inst.text}`);
  log(`installed: notAfter=${inst.json.notAfter} persisted=${inst.json.persisted}`);
  if (!inst.json.persisted) throw new Error('installed but NOT persisted to the sealed store -- fleet boxes will not get it');

  // 4. See it served.
  // Workers receive the certificate over IPC a moment after the primary
  // installs it, and a fresh connection may land on any of them: allow a
  // short window before calling it a failure.
  let servedFp = 'unknown';
  for (let i = 0; i < 10; i += 1) {
    const after = await enclave('/health', { headers: { authorization: '' } });
    servedFp = after.served ? after.served.fingerprint256 : 'unknown';
    if (servedFp === leaf.fingerprint256) break;
    await new Promise((r) => setTimeout(r, 1500));
  }
  log(`served now: fingerprint256=${servedFp}`);
  if (servedFp !== leaf.fingerprint256) throw new Error('the box is not serving the certificate it just installed');
  console.log(`RENEWED ${names.join(',')} notAfter=${inst.json.notAfter}`);
}

main().catch((e) => { console.error(`[renew] FAILED: ${e.message}`); exit(1); });
