#!/usr/bin/env node
// Read the certificate the Azure STANDBY for api.ppq.ai serves and fail when
// it is close to expiry. Used by enclave-drift.yml (as one drift signal, kept
// clearly apart from the enclave's own certificate) and by azure-api-cert.yml
// as the final "did the renewal actually land" check.
//
// The standby is the App Service ppq-backend-us. Once api.ppq.ai's CNAME moves
// to the enclave the App Service's managed certificate can no longer renew
// (Azure re-validates the name through the CNAME), so the standby's
// certificate is renewed by scripts/renew-azure-cert-dns01.mjs instead, and
// this check is what notices if that stalls. The App Service is reached by
// its own hostname with SNI for the domain, so the check is independent of
// where the public name points.
//
// Usage: node scripts/check-azure-standby-cert.mjs [--domain api.ppq.ai]
//          [--host ppq-backend-us.azurewebsites.net] [--min-days 20]
// Exit 0 when the served certificate has at least --min-days left; 1 when it
// has fewer, or the standby could not be reached; 2 on usage.
import { argv, exit } from 'node:process';
import { AZURE_APP_HOST, DEFAULT_DOMAIN, daysLeft, describeCertificate, servedCertificate } from './lib/azureCert.mjs';

function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}
const DOMAIN = arg('domain', DEFAULT_DOMAIN);
const HOST = arg('host', AZURE_APP_HOST);
const MIN_DAYS = Number(arg('min-days', '20'));
if (!Number.isFinite(MIN_DAYS) || MIN_DAYS < 0) { console.error('--min-days must be a non-negative number'); exit(2); }

const tag = `[azure-standby] ${DOMAIN} on ${HOST}:`;
try {
  const cert = await servedCertificate({ host: HOST, servername: DOMAIN });
  const d = daysLeft(cert.validTo);
  console.log(`${tag} ${describeCertificate(cert)}`);
  if (!Number.isFinite(d)) { console.log(`${tag} PROBLEM: could not parse the certificate's expiry`); exit(1); }
  if (d < MIN_DAYS) {
    console.log(`${tag} PROBLEM: standby certificate expires in ${d.toFixed(1)} days (< ${MIN_DAYS}); renewal (azure-api-cert.yml) has stalled`);
    exit(1);
  }
  console.log(`${tag} OK: ${d.toFixed(1)} days left (>= ${MIN_DAYS})`);
} catch (e) {
  console.log(`${tag} PROBLEM: could not read the served certificate: ${e.message}`);
  exit(1);
}
