#!/usr/bin/env node
/**
 * PPQ enclave attestation verifier (reference client).
 *
 * Proves — cryptographically, before sending any query — that the endpoint is a
 * genuine AWS Nitro enclave running the exact published image, and that the TLS
 * connection terminates inside that enclave. This is what replaces the insecure
 * `curl -k` shortcut used during bring-up.
 *
 * Steps:
 *   1. Blind-fetch the enclave's TLS cert (authenticity established below, not by TLS).
 *   2. Fetch GET /attestation?nonce=<random> over a connection pinned to that exact
 *      cert (DER-equal; pinned-tls.mjs explains why the pin is not a `ca:` option).
 *   3. Verify the COSE_Sign1 signature with the document's leaf certificate.
 *   4. Verify the cert chain up to the pinned AWS Nitro root (fingerprint-checked).
 *   5. Check every cert's validity window.
 *   6. Check the document's nonce == ours (freshness / anti-replay).
 *   7. Check PCR0 == the expected published value (the code fingerprint).
 *   8. Check the document's public_key == SHA-256 of the TLS cert's SPKI
 *      (binds the attested identity to this exact TLS endpoint).
 *   9. Only if ALL pass, and only with --credit-id: send the chat request over a
 *      pinned connection. Without --credit-id the run stops after step 8, so the
 *      verifier can be pointed at production read-only.
 *
 * Usage:
 *   node verify.mjs --host <host or ip> --port 443 --expect-pcr0 <hex> \
 *     [--servername <sni>] [--credit-id <id>] [--model <slug>] [--prompt <text>]
 *
 * --servername defaults to --host for a hostname (the name the enclave's
 * certificate is issued for) and to the enclave's own name for a bare IP (the
 * host's :8443 forwarder during bring-up). Both fetches use the same SNI, so
 * the pinned cert is the one the attestation will be checked against; an
 * unknown SNI on the public name can reach a different TLS context (README,
 * Known gaps 3).
 */

import net from 'node:net';
import crypto, { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import cbor from 'cbor';
import { fetchPeerCertDer, pinnedRequest } from './pinned-tls.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AWS_ROOT_PEM = readFileSync(join(__dirname, 'aws-nitro-root-g1.pem'));

// ── args ──────────────────────────────────────────────────────────────────────
function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const HOST = arg('host', '127.0.0.1');
const PORT = Number(arg('port', '8443'));
// SNI for both the blind fetch and every pinned request (see header).
const SERVERNAME = arg('servername', net.isIP(HOST) ? 'ppq-enclave-proxy' : HOST);
const EXPECT_PCR0 = (arg('expect-pcr0', '') || '').toLowerCase();
const CREDIT_ID = arg('credit-id', '');
const MODEL = arg('model', 'openai/gpt-4o-mini');
const PROMPT = arg('prompt', 'Say hello in three words.');

if (!EXPECT_PCR0) {
  console.error('error: --expect-pcr0 <hex> is required (the published code fingerprint)');
  process.exit(2);
}

const ok = (m) => console.log(`  \x1b[32m✓\x1b[0m ${m}`);
const step = (m) => console.log(`\x1b[1m${m}\x1b[0m`);
function fail(m) {
  console.error(`  \x1b[31m✗ ${m}\x1b[0m`);
  console.error('\n\x1b[31mABORTED — not sending any query. The endpoint is NOT a verified enclave.\x1b[0m');
  process.exit(1);
}

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const spkiSha256 = (cert) =>
  sha256(cert.publicKey.export({ type: 'spki', format: 'der' }));
const getKey = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);

async function main() {
  step(`\nVerifying enclave at ${HOST}:${PORT}`);
  console.log(`  expected PCR0: ${EXPECT_PCR0}`);

  const peerDer = await fetchPeerCertDer({ host: HOST, port: PORT, servername: SERVERNAME });
  const peerCert = new X509Certificate(peerDer);
  const peerSpkiHex = spkiSha256(peerCert).toString('hex');
  ok(`fetched TLS cert (SPKI SHA-256 ${peerSpkiHex.slice(0, 16)}…, SNI ${SERVERNAME})`);
  // Every request from here on refuses any connection whose peer certificate
  // is not byte-identical to the one just fetched.
  const pin = { host: HOST, port: PORT, servername: SERVERNAME, expectedDer: peerDer };

  const nonce = crypto.randomBytes(16);
  const nonceHex = nonce.toString('hex');
  const attRes = await pinnedRequest(pin, `/attestation?nonce=${nonceHex}`);
  if (attRes.status !== 200) fail(`/attestation returned HTTP ${attRes.status}`);
  const attJson = JSON.parse(attRes.body.toString());
  const doc = Buffer.from(attJson.attestation_document_b64, 'base64');
  ok(`fetched attestation document over pinned TLS (${doc.length} bytes)`);

  // ── parse COSE_Sign1 = [protected, unprotected, payload, signature] ──────────
  let cose = cbor.decodeFirstSync(doc);
  if (cose && cose.tag === 18 && Array.isArray(cose.value)) cose = cose.value;
  if (!Array.isArray(cose) || cose.length !== 4) fail('malformed COSE_Sign1');
  const [protectedBstr, , payloadBstr, signature] = cose;
  const payload = cbor.decodeFirstSync(payloadBstr);

  // Pin the signature algorithm to ES384 (COSE alg -35). Without this, an
  // attacker-supplied leaf could use a different key type / algorithm.
  const protectedHdr = cbor.decodeFirstSync(protectedBstr);
  const alg = protectedHdr instanceof Map ? protectedHdr.get(1) : protectedHdr?.[1];
  if (alg !== -35) fail(`unexpected COSE algorithm ${alg} (expected -35 / ES384)`);

  const leafDer = getKey(payload, 'certificate');
  const leaf = new X509Certificate(Buffer.from(leafDer));

  // ── 3. COSE signature (ES384) over the Sig_structure with the leaf key ───────
  const sigStructure = cbor.encode(['Signature1', protectedBstr, Buffer.alloc(0), payloadBstr]);
  const sigValid = crypto.verify(
    'sha384',
    sigStructure,
    { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' },
    signature,
  );
  if (!sigValid) fail('COSE signature invalid');
  ok('COSE_Sign1 signature valid (signed by the document leaf certificate)');

  // ── 4/5. chain to the AWS Nitro root + validity ─────────────────────────────
  const cabundle = getKey(payload, 'cabundle').map((d) => Buffer.from(d));
  const chain = [...cabundle, Buffer.from(leafDer)].map((d) => new X509Certificate(d));
  const awsRoot = new X509Certificate(AWS_ROOT_PEM);
  if (chain[0].fingerprint256 !== awsRoot.fingerprint256)
    fail('chain does not root in the AWS Nitro Enclaves root certificate');
  if (!chain[0].verify(chain[0].publicKey)) fail('root certificate self-signature invalid');
  for (let i = 1; i < chain.length; i++) {
    const issuer = chain[i - 1];
    // CRITICAL: every issuing cert MUST be a CA. X509Certificate.verify() only
    // checks the signature, not basicConstraints — without this a valid AWS
    // end-entity (leaf) cert could be used to sign a forged attestation, since
    // anyone can boot their own Nitro enclave and get an AWS-issued leaf.
    if (issuer.ca !== true) fail(`chain cert ${i - 1} is not a CA (basicConstraints CA:FALSE)`);
    if (!chain[i].verify(issuer.publicKey)) fail(`certificate chain broken at link ${i}`);
  }
  const now = Date.now();
  for (const c of chain) {
    if (Date.parse(c.validFrom) > now || Date.parse(c.validTo) < now)
      fail(`certificate outside validity window (${c.subject})`);
  }
  ok(`certificate chain (${chain.length} certs) roots in AWS Nitro root, all in validity`);

  // ── 6. nonce freshness ───────────────────────────────────────────────────────
  const docNonce = getKey(payload, 'nonce');
  if (!docNonce || Buffer.from(docNonce).toString('hex') !== nonceHex)
    fail('nonce mismatch (possible replay)');
  ok('nonce matches (fresh, not a replay)');

  // ── 7. PCR0 == expected published code fingerprint ──────────────────────────
  const pcrs = getKey(payload, 'pcrs');
  const pcr0 = Buffer.from(pcrs instanceof Map ? pcrs.get(0) : pcrs[0]).toString('hex');
  if (pcr0 !== EXPECT_PCR0) fail(`PCR0 mismatch\n      got:      ${pcr0}\n      expected: ${EXPECT_PCR0}`);
  ok(`PCR0 matches expected image (${pcr0.slice(0, 24)}…)`);

  // ── 8. bind attested identity to the TLS endpoint ───────────────────────────
  // The enclave commits the TLS cert SPKI hash in `user_data` (public_key now
  // carries the HPKE key for browser/EHBP clients).
  const committed = Buffer.from(getKey(payload, 'user_data') || []).toString('hex');
  if (committed !== peerSpkiHex)
    fail('attestation user_data does not match the TLS cert (endpoint not bound to enclave)');
  ok('attestation is bound to this TLS cert (endpoint IS the attested enclave)');

  if (!CREDIT_ID) {
    console.log('\n\x1b[32m\x1b[1mENCLAVE VERIFIED\x1b[0m — no --credit-id given, so no query is sent.\n');
    return;
  }
  console.log('\n\x1b[32m\x1b[1mENCLAVE VERIFIED\x1b[0m — sending query over the attested, pinned connection.\n');

  // ── 9. send the real query over the now-trusted pinned connection ───────────
  const reqBody = JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: PROMPT }],
    max_tokens: 40,
    stream: true,
  });
  const chatRes = await pinnedRequest(pin, '/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-credit-id': CREDIT_ID,
      'x-query-source': 'api',
      'x-request-id': `verify-${nonceHex.slice(0, 12)}`,
    },
    body: reqBody,
  });
  const text = (chatRes.body.toString().match(/"content":"([^"]*)"/g) || [])
    .map((m) => m.replace(/"content":"|"$/g, ''))
    .join('');
  console.log(`  model:   ${MODEL}`);
  console.log(`  answer:  ${text || '(no content)'}`);
  console.log('\n\x1b[32mDone — query sent WITHOUT -k, over a cryptographically verified enclave.\x1b[0m');
}

main().catch((e) => fail(e.message));
