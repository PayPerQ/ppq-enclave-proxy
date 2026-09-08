#!/usr/bin/env node
// Compare what we PUBLISH against what the enclave is ACTUALLY serving, from
// the outside, the way a verifying client would.
//
// WHY THIS EXISTS
// ---------------
// scripts/check-drift.py reads the running measurement over SSM -- from the
// inside. That cannot catch the failure a client sees: a published PCR0 that no
// live attestation document carries, an attestation whose `user_data` does not
// match the certificate the TLS handshake presented, or a public key that is
// advertised in JSON but not committed in the signed document. TrustedRouter
// published a PCR0 that matched no running enclave after a rebuild and nothing
// compared the two (their trust-drift.yml exists for that reason); this repo
// produced the same shape of failure twice in one day on 2026-09-07. So this
// walks the client's chain, not the operator's:
//
//   1. TLS-connect to the hostname; hash the SPKI of the certificate served.
//   2. GET /attestation with a fresh nonce; verify the COSE document against
//      the pinned AWS Nitro root (client/browser-verify.mjs -- the same code
//      the browser runs).
//   3. PCR0 in the SIGNED document must be the published `current`, or, during
//      a rollover, another `accepted_pcr0` entry.
//   4. `user_data` in the SIGNED document == the SPKI hash from step 1 == the
//      `cert_spki_sha256` the JSON advertises. This is the #52 property; until
//      TLS moved into the enclave it could not hold.
//   5. `public_key` in the SIGNED document == the `hpke_public_key` advertised.
//   6. /health `hpke_identity` must be `store` once that field exists (#52
//      scaling): `generated` means the next restart rotates the key browsers
//      seal to.
//
// Exit status is non-zero on any disagreement. Nothing here is billed and no
// prompt is sent.
//
//   node scripts/check-live-attestation.mjs [--host enclave.ppq.ai] [--published attestation/published-pcr.json]
import { argv, exit } from 'node:process';
import { readFileSync } from 'node:fs';
import { randomBytes, createHash, X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import { verifyAttestation } from '../client/browser-verify.mjs';

function arg(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}
const HOST = arg('host', 'enclave.ppq.ai');
const PUBLISHED = arg('published', 'attestation/published-pcr.json');

const problems = [];
const problem = (m) => { problems.push(m); console.log(`[!!] ${m}`); };
const ok = (m) => console.log(`[ok] ${m}`);
const note = (m) => console.log(`[..] ${m}`);

function servedSpkiSha256(host) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port: 443, servername: host, timeout: 15_000 }, () => {
      try {
        const raw = sock.getPeerCertificate(false)?.raw;
        if (!raw) throw new Error('no peer certificate');
        const spki = new X509Certificate(raw).publicKey.export({ type: 'spki', format: 'der' });
        resolve({ spki: createHash('sha256').update(spki).digest('hex'), authorized: sock.authorized });
      } catch (e) {
        reject(e);
      } finally {
        sock.end();
      }
    });
    sock.on('error', reject);
    sock.on('timeout', () => { sock.destroy(); reject(new Error('TLS connect timed out')); });
  });
}

async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.json();
}

async function main() {
  const doc = JSON.parse(readFileSync(PUBLISHED, 'utf8'));
  const current = String(doc.current.pcr0).toLowerCase();
  const accepted = (doc.accepted_pcr0 || []).map((p) => String(p).toLowerCase());
  console.log(`host              : ${HOST}`);
  console.log(`published current : ${current}`);

  // 1. What TLS actually presented.
  let served;
  try {
    served = await servedSpkiSha256(HOST);
    ok(`TLS handshake with ${HOST} (chain ${served.authorized ? 'trusted' : 'NOT trusted'} by Node's CA store)`);
    if (!served.authorized) problem(`${HOST} presents a certificate the public CA store does not trust`);
  } catch (e) {
    problem(`could not complete a TLS handshake with ${HOST}: ${e.message}`);
    return;
  }

  // 2. The signed attestation, with a nonce only this run knows.
  const nonceHex = randomBytes(32).toString('hex');
  let att;
  try {
    att = await getJson(`https://${HOST}/attestation?nonce=${nonceHex}`);
  } catch (e) {
    problem(`could not fetch /attestation: ${e.message}`);
    return;
  }

  // 3. Verify against `current`; a rollover legitimately serves another
  //    accepted entry, and that must still be a fully verified document.
  let verified;
  let livePcr0 = current;
  try {
    verified = await verifyAttestation(att.attestation_document_b64, { expectedPcr0: current, nonceHex });
    ok('signed attestation carries the published current measurement');
  } catch (e) {
    const got = /got:\s+([0-9a-f]{96})/.exec(String(e.message))?.[1];
    if (got && accepted.includes(got)) {
      verified = await verifyAttestation(att.attestation_document_b64, { expectedPcr0: got, nonceHex });
      livePcr0 = got;
      note(`live measurement ${got.slice(0, 16)}… is accepted but not current — rollover in progress`);
    } else if (got) {
      problem(`live measurement ${got.slice(0, 16)}… is in neither current nor accepted_pcr0 — verifying clients are falling back right now`);
      return;
    } else {
      problem(`attestation document failed verification: ${e.message}`);
      return;
    }
  }
  console.log(`live PCR0         : ${livePcr0}`);

  // 4. The served key is the attested key.
  const advertised = String(att.cert_spki_sha256 || '').toLowerCase();
  if (verified.userDataHex !== served.spki) {
    problem(`attested user_data ${verified.userDataHex.slice(0, 16)}… != served SPKI ${served.spki.slice(0, 16)}… — TLS is not terminating on the attested key`);
  } else {
    ok(`served certificate SPKI is the one the signed attestation commits to (${served.spki.slice(0, 16)}…)`);
  }
  if (advertised !== served.spki) {
    problem(`advertised cert_spki_sha256 ${advertised.slice(0, 16)}… != served SPKI ${served.spki.slice(0, 16)}…`);
  }

  // 5. The advertised HPKE key is the signed one.
  const hpkeAdvertised = String(att.hpke_public_key || '').toLowerCase();
  if (hpkeAdvertised !== verified.hpkePublicKeyHex) {
    problem('advertised hpke_public_key is not the public_key in the signed attestation');
  } else {
    ok(`advertised HPKE public key is committed in the signed attestation (${hpkeAdvertised.slice(0, 16)}…)`);
  }

  // 6. Identity provenance, once the image reports it.
  try {
    const health = await getJson(`https://${HOST}/health`);
    if (!('hpke_identity' in health)) {
      note('/health does not report hpke_identity yet (image predates identity persistence)');
    } else if (health.hpke_identity === 'store') {
      ok('EHBP identity came from the sealed store');
    } else {
      problem(
        `EHBP identity is '${health.hpke_identity}' (persisted=${health.hpke_identity_persisted}) — ` +
        'browsers that sealed to this key stop decrypting at the next restart',
      );
    }
  } catch (e) {
    problem(`could not read /health: ${e.message}`);
  }
}

main()
  .then(() => {
    console.log(problems.length ? `\nLIVE ATTESTATION: ${problems.length} problem(s)` : '\nLIVE ATTESTATION: clean');
    exit(problems.length ? 1 : 0);
  })
  .catch((e) => {
    console.log(`[!!] unexpected: ${e.stack || e.message}`);
    exit(2);
  });
