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
//
// `--directory staging` never installs (a staging chain is not browser
// trusted); it proves the CSR -> DNS-01 -> chain path end to end and checks
// the chain is for the enclave's key, then discards it.
import { argv, env, exit } from 'node:process';
import { Resolver } from 'node:dns/promises';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import {
  AcmeClient, LETSENCRYPT_PROD, LETSENCRYPT_STAGING, dnsTxtValue, generateAccountKey,
  keyAuthorization, pollUntil,
} from '../enclave/src/acme.mjs';

function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}
const HOST = arg('host', 'enclave-direct.ppq.ai');
const DIRECTORY = arg('directory', 'prod') === 'staging' ? LETSENCRYPT_STAGING : LETSENCRYPT_PROD;
const STAGING = DIRECTORY === LETSENCRYPT_STAGING;
const MIN_DAYS = Number(arg('min-days', '30'));
const FORCE = argv.includes('--force');
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
      headers: { authorization: `Bearer ${CI_TOKEN}`, 'content-type': 'application/json', ...headers } }, (res) => {
      const raw = res.socket.getPeerCertificate(false)?.raw;
      const served = raw ? new X509Certificate(raw) : null;
      let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; });
      res.on('end', () => {
        let json = null; try { json = JSON.parse(b); } catch { /* not json */ }
        resolve({ status: res.statusCode, json, text: b, served });
      });
    });
    req.on('timeout', () => req.destroy(new Error('enclave request timed out')));
    req.on('error', reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}

async function godaddy(method, path, body) {
  const r = await fetch(`https://api.godaddy.com/v1/domains/${ZONE}${path}`, {
    method, headers: { authorization: `Bearer ${GD_TOKEN}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok && r.status !== 404) throw new Error(`GoDaddy ${method} ${path} -> ${r.status}: ${await r.text()}`);
  return r.status;
}

async function authoritativeResolver() {
  const r = new Resolver();
  const ns = await r.resolveNs(ZONE);
  const ips = (await Promise.all(ns.slice(0, 2).map((n) => r.resolve4(n).catch(() => [])))).flat();
  if (!ips.length) throw new Error('could not resolve the zone nameservers');
  const auth = new Resolver(); auth.setServers(ips);
  return auth;
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
  //    duplicate CERTIFICATES, not accounts.
  const accountKey = generateAccountKey().privateKey;
  const client = new AcmeClient({ directoryUrl: DIRECTORY, accountKey, fetchImpl: fetch });
  log(`registering against ${DIRECTORY}`);
  await client.register(env.ACME_EMAIL || undefined);
  const { order, url: orderUrl } = await client.newOrder(names);
  const auth = await authoritativeResolver();
  const placed = [];
  try {
    for (const authzUrl of order.authorizations || []) {
      const { authz, challenge } = await client.dnsChallenge(authzUrl);
      const name = authz.identifier.value;
      const txt = dnsTxtValue(keyAuthorization(challenge.token, accountKey));
      const rr = `_acme-challenge.${name.replace(new RegExp(`\\.${ZONE.replace('.', '\\.')}$`), '')}`;
      await godaddy('PUT', `/records/TXT/${rr}`, [{ data: txt, ttl: 600 }]);
      placed.push(rr);
      log(`TXT ${rr}.${ZONE} = ${txt}`);
      // Wait until the zone's own nameservers serve it; the CA asks them.
      await pollUntil(
        async () => (await auth.resolveTxt(`${rr}.${ZONE}`).catch(() => [])).flat(),
        (v) => v.includes(txt),
        { attempts: 30, intervalMs: 5000 },
      );
      log(`TXT visible at the authoritative nameservers; asking the CA to validate ${name}`);
      await client.acceptChallenge(challenge.url);
      const done = await pollUntil(() => client.fetchResource(authzUrl), (a) => a.status === 'valid' || a.status === 'invalid', { attempts: 30, intervalMs: 3000 });
      if (done.status !== 'valid') throw new Error(`authorization for ${name} ${done.status}: ${JSON.stringify(done.challenges?.find((x) => x.type === 'dns-01')?.error || {})}`);
      log(`${name} validated`);
    }
  } finally {
    for (const rr of placed) {
      await godaddy('DELETE', `/records/TXT/${rr}`).then((s) => log(`cleaned TXT ${rr} (${s})`)).catch((e) => log(`could not clean TXT ${rr}: ${e.message}`));
    }
  }
  log('finalizing');
  await client.finalize(order.finalize, csrDer);
  const fin = await pollUntil(() => client.fetchResource(orderUrl), (o) => o.status === 'valid' || o.status === 'invalid', { attempts: 30, intervalMs: 3000 });
  if (fin.status !== 'valid') throw new Error(`order ${fin.status}`);
  const chain = await client.downloadCertificate(fin.certificate);
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
  const after = await enclave('/health', { headers: { authorization: '' } });
  const servedNotAfter = after.served ? new Date(after.served.validTo).toISOString() : 'unknown';
  log(`served now: notAfter=${servedNotAfter}`);
  if (servedNotAfter !== new Date(leaf.validTo).toISOString()) throw new Error('the box is not serving the certificate it just installed');
  console.log(`RENEWED ${names.join(',')} notAfter=${inst.json.notAfter}`);
}

main().catch((e) => { console.error(`[renew] FAILED: ${e.message}`); exit(1); });
