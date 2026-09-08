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
//   1. GET /attestation with a fresh nonce and hash the SPKI of the
//      certificate presented on THAT connection (the signed `user_data` is a
//      per-connection commitment, so any other connection is the wrong one).
//   2. Verify the COSE document against the pinned AWS Nitro root
//      (client/browser-verify.mjs -- the same code the browser runs).
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
import https from 'node:https';
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

/**
 * GET a JSON document and report the SPKI of the certificate presented on THAT
 * connection. One connection per call (`agent: false`), because the signed
 * `user_data` in an attestation commits to the certificate of the connection
 * that fetched it -- comparing it to a certificate seen on some other
 * connection would, behind a load balancer, compare backend A to backend B.
 */
function getJsonWithPeer(url) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'GET', agent: false, timeout: 20_000 }, (res) => {
      let spki = null;
      let authorized = null;
      try {
        const raw = res.socket.getPeerCertificate(false)?.raw;
        if (raw) {
          const der = new X509Certificate(raw).publicKey.export({ type: 'spki', format: 'der' });
          spki = createHash('sha256').update(der).digest('hex');
        }
        authorized = res.socket.authorized;
      } catch (e) {
        return reject(e);
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`${url} -> HTTP ${res.statusCode}`));
        try {
          resolve({ json: JSON.parse(body), spki, authorized });
        } catch (e) {
          reject(new Error(`${url} -> not JSON (${e.message})`));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  const doc = JSON.parse(readFileSync(PUBLISHED, 'utf8'));
  const current = String(doc.current.pcr0).toLowerCase();
  const accepted = (doc.accepted_pcr0 || []).map((p) => String(p).toLowerCase());
  console.log(`host              : ${HOST}`);
  console.log(`published current : ${current}`);

  // 1+2. The signed attestation, with a nonce only this run knows, and the
  //      certificate presented on the very connection that fetched it.
  const nonceHex = randomBytes(32).toString('hex');
  let att;
  let served;
  try {
    const r = await getJsonWithPeer(`https://${HOST}/attestation?nonce=${nonceHex}`);
    att = r.json;
    served = { spki: r.spki, authorized: r.authorized };
    if (!served.spki) throw new Error('no peer certificate on the attestation connection');
    ok(`TLS handshake with ${HOST} (chain ${served.authorized ? 'trusted' : 'NOT trusted'} by Node's CA store)`);
    if (!served.authorized) problem(`${HOST} presents a certificate the public CA store does not trust`);
  } catch (e) {
    problem(`could not fetch /attestation over TLS: ${e.message}`);
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

  // 6. Identity provenance, once the image reports it. /health is a separate
  //    connection; if it lands on a backend with a different certificate,
  //    that is itself the drift the shared-identity design forbids.
  try {
    const r = await getJsonWithPeer(`https://${HOST}/health`);
    if (r.spki !== served.spki) {
      problem(`/health answered by a backend presenting a different certificate (${String(r.spki).slice(0, 16)}… vs ${served.spki.slice(0, 16)}…) — boxes are not sharing one identity`);
    }
    const health = r.json;
    if (!('hpke_identity' in health)) {
      note('/health does not report hpke_identity yet (image predates identity persistence)');
    } else if (health.hpke_identity === 'store') {
      ok('EHBP identity came from the sealed store');
    } else if (health.hpke_identity === 'rejected') {
      problem('the sealed store holds an EHBP identity this image REFUSED to load and is leaving untouched — needs a human (version bug, bad edit, or truncated write)');
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
