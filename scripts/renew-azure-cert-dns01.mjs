#!/usr/bin/env node
// Renew the Azure STANDBY's certificate for api.ppq.ai from CI with DNS-01.
//
// WHY
// ---
// api.ppq.ai moves onto the enclave. The App Service `ppq-backend-us` stays
// behind it as the hot standby for the name, but its App Service managed
// certificate only renews while api.ppq.ai's CNAME points at the app -- which
// stops being true at the flip. The enclave's certificate cannot be reused:
// its key never leaves the enclave and Azure needs the key to terminate TLS.
// So the standby gets a Let's Encrypt certificate of its own, with its OWN
// key generated on the runner, proven over DNS-01 with the same GoDaddy token
// the enclave renewal uses, packed into a PFX and bound on the App Service.
// The two certificates share nothing but the CA: separate keys, separate
// SAN sets (this one is api.ppq.ai alone, so it does not draw on the
// enclave certificate's duplicate-certificate budget).
//
// The proof-of-control and order flow is the enclave renewal's, verbatim,
// through scripts/lib/dns01.mjs. What differs is only the key custody
// (runner, not enclave), the chain check (done here against the same pinned
// ISRG roots the enclave applies) and the install (Azure, not /acme/install).
//
// Usage:
//   GODADDY_API_TOKEN=… node scripts/renew-azure-cert-dns01.mjs \
//     [--domain api.ppq.ai] [--directory prod|staging] [--min-days 30] [--force] [--no-upload]
//     [--app-host ppq-backend-us.azurewebsites.net] [--resource-group ppq-backend] [--app ppq-backend-us]
//   env: GODADDY_API_TOKEN (required), ACME_EMAIL (optional), AZURE_SUBSCRIPTION_ID (optional;
//        `az login` has already selected one in CI)
//
// `--directory staging` proves the whole path and checks the leaf is for the
// generated key, prints the chain, and never uploads (a staging chain is not
// browser-trusted and cannot be verified against the ISRG roots). Prints
// `RENEWED <domain> notAfter=…` after a successful bind, `SKIP …` when not due.
// Exit 0 ok/skip, 2 usage, 1 failure. The key and the PFX password are never
// printed.
import { argv, env, exit } from 'node:process';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, X509Certificate } from 'node:crypto';
import {
  AcmeClient, LETSENCRYPT_PROD, LETSENCRYPT_STAGING, generateAccountKey, generateCertKey, makeCsr,
} from '../enclave/src/acme.mjs';
import { verifyChainToRoots } from '../enclave/src/acmeRunner.mjs';
import { LETS_ENCRYPT_ROOTS_PEM } from '../enclave/src/trustRoots.mjs';
import { createDns01 } from './lib/dns01.mjs';
import {
  AZURE_APP, AZURE_APP_HOST, AZURE_RESOURCE_GROUP, DEFAULT_DOMAIN,
  azBindArgs, azHostnameListArgs, azUploadArgs, boundThumbprint, certificateNames, daysLeft, describeCertificate,
  parseThumbprint, pfxExportArgs, publicKeyMatches, renewalDecision, servedCertificate, spkiSha256, thumbprintOf,
} from './lib/azureCert.mjs';

function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}
const DOMAIN = arg('domain', DEFAULT_DOMAIN);
const DIRECTORY_NAME = arg('directory', 'prod');
const DIRECTORY = DIRECTORY_NAME === 'staging' ? LETSENCRYPT_STAGING : LETSENCRYPT_PROD;
const STAGING = DIRECTORY === LETSENCRYPT_STAGING;
const MIN_DAYS = Number(arg('min-days', '30'));
const DNS_SETTLE_S = Number(arg('dns-settle', '45'));
const ORDER_ATTEMPTS = 2;
const FORCE = argv.includes('--force');
const UPLOAD = !argv.includes('--no-upload') && !STAGING;
const APP_HOST = arg('app-host', AZURE_APP_HOST);
const RESOURCE_GROUP = arg('resource-group', AZURE_RESOURCE_GROUP);
const APP = arg('app', AZURE_APP);
const SUBSCRIPTION = env.AZURE_SUBSCRIPTION_ID || undefined;
const ZONE = 'ppq.ai';
const GD_TOKEN = env.GODADDY_API_TOKEN || '';
const log = (m) => console.log(`[renew] ${m}`);

if (!['prod', 'staging'].includes(DIRECTORY_NAME)) { console.error('--directory must be prod or staging'); exit(2); }
if (!Number.isFinite(MIN_DAYS) || MIN_DAYS < 0) { console.error('--min-days must be a non-negative number'); exit(2); }
if (!/^[a-z0-9.-]+$/i.test(DOMAIN) || DOMAIN.includes('*') || !(DOMAIN === ZONE || DOMAIN.endsWith(`.${ZONE}`))) {
  console.error(`--domain must be a single non-wildcard name under ${ZONE}`); exit(2);
}
if (!GD_TOKEN) { console.error('GODADDY_API_TOKEN is required'); exit(2); }

/**
 * Run a command and return stdout. Built on spawnSync rather than
 * execFileSync because the latter puts the WHOLE argv in its error message,
 * and `az … ssl upload` carries the PFX password in argv; here a failure
 * reports stderr only.
 */
function run(cmd, args, { extraEnv = {}, what = cmd } = {}) {
  const r = spawnSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...env, ...extraEnv }, maxBuffer: 16 * 1024 * 1024 });
  if (r.error) throw new Error(`${what}: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${what} exited ${r.status}: ${String(r.stderr || '').trim().slice(-2000)}`);
  return String(r.stdout || '');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function currentlyServed() {
  try {
    return await servedCertificate({ host: APP_HOST, servername: DOMAIN });
  } catch (e) {
    log(`could not read the certificate ${APP_HOST} serves for ${DOMAIN}: ${e.message}`);
    return null;
  }
}

async function main() {
  // 0. Does it need renewing? Ask the App Service itself, by its own
  //    hostname with SNI for the domain, so the answer does not depend on
  //    where api.ppq.ai's CNAME points today.
  const served = await currentlyServed();
  if (served) log(`${DOMAIN} on ${APP_HOST}: ${describeCertificate(served)}`);
  const decision = renewalDecision({ daysLeft: served ? daysLeft(served.validTo) : NaN, minDays: MIN_DAYS, force: FORCE });
  if (!decision.renew) {
    log(`${decision.reason}; nothing to do (--force to renew anyway)`);
    console.log(`SKIP ${DOMAIN} notAfter=${new Date(served.validTo).toISOString()}`);
    return;
  }
  log(`renewing: ${decision.reason}`);

  // 1. Fresh key on the runner, CSR over it. Its own SAN set: just the domain.
  const key = generateCertKey();
  const names = [DOMAIN];
  const csrDer = makeCsr(names, key.privateKey);
  log(`CSR for ${names.join(', ')} (${csrDer.length} bytes DER) spki_sha256=${spkiSha256(key.privateKey)}`);

  // 2. Order with DNS-01 -- the enclave renewal's flow, shared verbatim.
  const accountKey = generateAccountKey().privateKey;
  const client = new AcmeClient({ directoryUrl: DIRECTORY, accountKey, fetchImpl: fetch });
  log(`registering against ${DIRECTORY}`);
  await client.register(env.ACME_EMAIL || undefined);
  const dns01 = createDns01({ zone: ZONE, godaddyToken: GD_TOKEN, log, settleSeconds: DNS_SETTLE_S, orderAttempts: ORDER_ATTEMPTS });
  const chain = await dns01.obtainCertificate({ client, accountKey, names, csrDer });
  const leaf = new X509Certificate(chain);
  log(`issued: subject=${leaf.subject.replace(/\n/g, ' ')} issuer=${leaf.issuer.replace(/\n/g, ' ')} notAfter=${new Date(leaf.validTo).toISOString()}`);

  // 3. Is it for OUR key and OUR name? Prod additionally: does it chain to the
  //    pinned ISRG roots -- the same check the enclave applies at /acme/install.
  if (!publicKeyMatches(leaf, key.privateKey)) throw new Error('issued leaf is not for the generated key');
  const covered = certificateNames(leaf);
  for (const n of names) if (!covered.includes(n)) throw new Error(`issued certificate does not cover ${n} (has ${covered.join(', ')})`);
  if (STAGING) {
    log('staging: leaf is for the generated key and covers the name; chain (not trusted, not uploaded):');
    console.log(chain.trim());
    console.log(`STAGING-OK ${DOMAIN} notAfter=${new Date(leaf.validTo).toISOString()}`);
    return;
  }
  const { depth } = verifyChainToRoots(chain, LETS_ENCRYPT_ROOTS_PEM);
  log(`chain verified against the pinned ISRG roots (${depth} certificates)`);
  if (!UPLOAD) {
    log('not uploading (--no-upload)');
    return;
  }

  // 4. PFX -> App Service. Key and PFX live only in a 0700 temp dir for the
  //    seconds this takes; the PFX password is random per run and reaches
  //    openssl through the environment, never argv.
  const thumbprint = thumbprintOf(leaf);
  const dir = mkdtempSync(join(tmpdir(), 'azure-cert-'));
  try {
    chmodSync(dir, 0o700);
    const keyPath = join(dir, 'key.pem');
    const chainPath = join(dir, 'chain.pem');
    const pfxPath = join(dir, 'cert.pfx');
    writeFileSync(keyPath, key.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(chainPath, chain, { mode: 0o600 });
    const password = randomBytes(32).toString('base64url');
    run('openssl', pfxExportArgs({ keyPath, chainPath, outPath: pfxPath, name: DOMAIN, passEnv: 'PFXPASS' }), { extraEnv: { PFXPASS: password }, what: 'openssl pkcs12 -export' });
    chmodSync(pfxPath, 0o600);
    log(`PFX built; uploading to ${RESOURCE_GROUP}/${APP}`);
    const target = { resourceGroup: RESOURCE_GROUP, app: APP, subscription: SUBSCRIPTION };
    const uploaded = parseThumbprint(run('az', azUploadArgs({ pfxPath, password, certificateName: `${DOMAIN}-le-${new Date(leaf.validFrom).toISOString().slice(0, 10)}`, ...target }), { what: 'az webapp config ssl upload' }));
    if (uploaded !== thumbprint) throw new Error(`uploaded thumbprint ${uploaded} is not the issued leaf's ${thumbprint}`);
    log(`uploaded: thumbprint=${uploaded}`);
    run('az', azBindArgs({ thumbprint, hostname: DOMAIN, ...target }), { what: 'az webapp config ssl bind' });
    const bound = boundThumbprint(run('az', azHostnameListArgs(target), { what: 'az webapp config hostname list' }), DOMAIN);
    if (!bound || bound.thumbprint !== thumbprint) throw new Error(`hostname binding for ${DOMAIN} shows ${JSON.stringify(bound)}, expected thumbprint ${thumbprint}`);
    log(`bound: ${DOMAIN} sslState=${bound.sslState} thumbprint=${bound.thumbprint}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // 5. See it served. Azure's front ends pick a rebinding up within a short
  //    while; allow a window before calling it a failure.
  let after = null;
  for (let i = 0; i < 20; i += 1) {
    after = await currentlyServed();
    if (after && thumbprintOf(after) === thumbprint) break;
    await sleep(6000);
  }
  if (!after || thumbprintOf(after) !== thumbprint) {
    throw new Error(`${APP_HOST} is not serving the certificate just bound for ${DOMAIN} (serving ${after ? thumbprintOf(after) : 'nothing readable'})`);
  }
  log(`served now: ${describeCertificate(after)}`);
  console.log(`RENEWED ${DOMAIN} notAfter=${new Date(after.validTo).toISOString()} spki_sha256=${spkiSha256(after)}`);
}

main().catch((e) => { console.error(`[renew] FAILED: ${e.message}`); exit(1); });
