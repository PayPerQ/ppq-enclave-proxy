#!/usr/bin/env node
// Verify an attested routing receipt end to end.
//
// WHAT THIS PROVES
// ----------------
// The enclave states, in a signature you can check, which upstream host its own
// TLS validated against for your request. The chain is four links, and this
// script walks all four rather than asserting any of them:
//
//   1. GET /attestation?nonce=… -> a COSE document containing `user_data`,
//      whose signature, certificate chain (to the pinned AWS Nitro root),
//      nonce and PCR0 are all VERIFIED (client/browser-verify.mjs)
//   2. take the certificate SPKI and SHA-256 it
//   3. require that hash to equal the document's `user_data`
//        -> the key is committed to by the Nitro Security Module, so the host
//           cannot substitute its own
//   4. verify the receipt signature against that SPKI
//        -> the receipt came from the measured enclave, not from PayPerQ
//
// Steps 1 and 3 are the load-bearing ones. Without the signature check in 1 a
// host could serve a document it wrote itself, and without 3 it could hand you
// any key and sign anything with it.
//
// WHAT THIS DOES NOT PROVE
// ------------------------
// Stated plainly, because a verification tool that oversells is worse than none:
//
// * **That the measurement is one you should trust.** The document's PCR0 must
//   be the one given with `--pcr0`, or else one of `accepted_pcr0` in the
//   checkout's `attestation/published-pcr.json` (`--published <file>`). Whether
//   that value corresponds to the source you read is the Sigstore provenance on
//   the build that produced it, which this script does not check.
// * **That a receipt belongs to a particular request.** A receipt carries no
//   request id, time or response digest, so a saved one shows that the enclave
//   signed that routing statement, not which exchange it was signed for.
// * **A receipt saved before the certificate was renewed.** `--sse` verifies
//   against the key the enclave attests to NOW; a receipt signed by an earlier
//   certificate's key fails here even though it was genuine.
// * **On an OpenRouter route the guarantee stops at OpenRouter's door.**
//   OpenRouter selects the underlying provider itself. The receipt says so via
//   `upstream_selects_provider: true`, and a reader who ignores that field will
//   conclude more than the receipt claims.
// * **It says nothing about what happened to your data at the provider.**
//   Only where the request went.
//
// Usage:
//   node client/verify-receipt.mjs                       # live request, default host
//   node client/verify-receipt.mjs --key sk-...           # authenticated live request
//   node client/verify-receipt.mjs --sse saved.txt        # verify a stream you saved
//   node client/verify-receipt.mjs --pcr0 <96-hex>        # require exactly this measurement
//   node client/verify-receipt.mjs --published <file>     # accept-list to use without --pcr0

import { argv, exit } from 'node:process';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, constants } from 'node:crypto';
import { verifyAttestation } from './browser-verify.mjs';

const RECEIPT_PREFIX = ': ppq-routing-receipt ';
const RECEIPT_SIG_PREFIX = ': ppq-routing-receipt-sig ';

function arg(name, fallback = undefined) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}

const HOST = arg('host', 'enclave.ppq.ai');
const MODEL = arg('model', 'anthropic/claude-sonnet-5');
const API_KEY = arg('key');
const SSE_FILE = arg('sse');
const WANT_PCR0 = arg('pcr0');
const PUBLISHED = arg('published', new URL('../attestation/published-pcr.json', import.meta.url).pathname);

let failures = 0;
const pass = (m) => console.log(`  ✓ ${m}`);
const fail = (m) => {
  failures++;
  console.log(`  ✗ ${m}`);
};

/**
 * Stop unless every check so far has passed.
 *
 * Called before the receipt's signature is checked: a signature that verifies
 * against a key nothing attested says nothing, and printing a tick beside it
 * is a false signal even when the run goes on to exit non-zero.
 */
function stopIfUntrusted() {
  if (!failures) return;
  console.log(`\nFAILED (${failures}) — the receipt was not checked: there is no attested key to check it against.\n`);
  exit(1);
}

async function fetchAttestation(nonceHex) {
  const res = await fetch(`https://${HOST}/attestation?nonce=${nonceHex}`);
  if (!res.ok) throw new Error(`/attestation returned ${res.status}`);
  return res.json();
}

/** The measurements this run accepts: the one named, else the published list. */
function acceptedMeasurements() {
  if (WANT_PCR0) return [WANT_PCR0.toLowerCase()];
  return JSON.parse(readFileSync(PUBLISHED, 'utf8')).accepted_pcr0.map((p) => p.toLowerCase());
}

/**
 * Verify the document against whichever accepted measurement it carries.
 * verifyAttestation takes one expected value, so a mismatch that names another
 * accepted entry (a rollover) is verified again, in full, against that entry.
 */
async function verifyDocument(docB64, nonceHex, accepted) {
  try {
    return { pcr0: accepted[0], ...(await verifyAttestation(docB64, { expectedPcr0: accepted[0], nonceHex })) };
  } catch (e) {
    const got = /got:\s+([0-9a-f]{96})/.exec(String(e.message))?.[1];
    if (!got || !accepted.includes(got)) throw e;
    return { pcr0: got, ...(await verifyAttestation(docB64, { expectedPcr0: got, nonceHex })) };
  }
}

async function fetchStream() {
  const headers = { 'content-type': 'application/json' };
  if (API_KEY) headers.authorization = `Bearer ${API_KEY}`;
  const res = await fetch(`https://${HOST}/v1/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: MODEL,
      stream: true,
      max_tokens: 12,
      messages: [{ role: 'user', content: 'Say OK.' }],
    }),
  });
  const text = await res.text();
  if (!text.includes(RECEIPT_PREFIX)) {
    throw new Error(
      `no receipt in the response (HTTP ${res.status}). ` +
        (API_KEY ? 'Body: ' : 'Try --key <sk-...>. Body: ') + text.slice(0, 200),
    );
  }
  return text;
}

function extract(sse) {
  const lines = sse.split('\n');
  const receiptLine = lines.find((l) => l.startsWith(RECEIPT_PREFIX));
  const sigLine = lines.find((l) => l.startsWith(RECEIPT_SIG_PREFIX));
  if (!receiptLine) throw new Error('no routing receipt found in this stream');
  return {
    json: receiptLine.slice(RECEIPT_PREFIX.length),
    sig: sigLine ? JSON.parse(sigLine.slice(RECEIPT_SIG_PREFIX.length)) : null,
  };
}

const main = async () => {
  console.log(`\nAttested routing receipt — ${HOST}\n`);

  const nonceHex = randomBytes(32).toString('hex');
  const att = await fetchAttestation(nonceHex);
  const spkiDer = Buffer.from(att.cert_spki_der, 'base64');

  console.log('1. attestation document');
  // Everything below reads fields OUT of this document, so it is verified
  // first: an unverified document is the host's word, whatever it contains.
  let verified = null;
  try {
    verified = await verifyDocument(att.attestation_document_b64, nonceHex, acceptedMeasurements());
    pass('COSE signature, certificate chain to the AWS Nitro root, and nonce verify');
    pass(`the measurement ${verified.pcr0.slice(0, 16)}… is ${WANT_PCR0 ? 'the one required' : 'on the published accept-list'}`);
  } catch (e) {
    fail(`the attestation document does NOT verify — stop here: ${String(e.message).split('\n').join(' ')}`);
  }
  const spkiHash = createHash('sha256').update(spkiDer).digest('hex');
  if (spkiHash === (att.cert_spki_sha256 || '').toLowerCase()) {
    pass('the SPKI hashes to the value the response advertises');
  } else {
    fail('advertised cert_spki_sha256 does not match the SPKI it shipped');
  }

  // The step that makes the rest mean anything: the key is the one the
  // verified document commits to in `user_data`.
  if (verified && verified.userDataHex === spkiHash) {
    pass('that hash is the user_data of the NSM-signed document (the host cannot swap the key)');
  } else {
    fail('the SPKI hash is NOT the signed document\'s user_data — stop here, the key is unattested');
  }

  stopIfUntrusted();

  console.log('\n2. routing receipt');
  const sse = SSE_FILE ? readFileSync(SSE_FILE, 'utf8') : await fetchStream();
  const { json, sig } = extract(sse);
  const receipt = JSON.parse(json);

  console.log(`   upstream        : ${receipt.upstream}`);
  console.log(`   route           : ${receipt.route}`);
  console.log(`   requested model : ${receipt.requested_model}`);
  console.log(`   model on wire   : ${receipt.upstream_model}`);
  if (receipt.skipped?.length) {
    for (const s of receipt.skipped) {
      console.log(`   skipped         : ${s.provider} (${s.reason}${s.field ? `: ${s.field}` : ''})`);
    }
  }

  if (!sig) {
    fail('receipt is UNSIGNED — trustworthy only inside the EHBP seal, not through nginx');
  } else {
    const key = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    // Options follow the KEY TYPE of the attested SPKI: ECDSA/SHA-256 (DER) for
    // an EC key, RSA-PSS (salt = digest) for RSA. The receipt's `alg` label is
    // checked against that -- it is informative, the key is authoritative.
    const sigOpts = key.asymmetricKeyType === 'ec'
      ? { key, dsaEncoding: 'der' }
      : { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
    const expectAlg = key.asymmetricKeyType === 'ec' ? 'ECDSA-SHA256' : 'RSA-PSS-SHA256';
    // Unconditional: a receipt with no `alg` is not exempt from the check.
    if (sig.alg !== expectAlg) fail(`receipt says alg=${sig.alg ?? '(missing)'} but the attested key is ${key.asymmetricKeyType} (expected ${expectAlg})`);
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(json, 'utf8'),
      sigOpts,
      Buffer.from(sig.sig, 'base64'),
    );
    if (ok) pass('signature verifies against the attested key');
    else fail('signature does NOT verify — this receipt did not come from that enclave');

    // Demonstrate the property rather than asserting it: flip the upstream and
    // show the signature breaks. Anyone can re-run this and watch it fail.
    const tampered = json.replace(`"upstream":"${receipt.upstream}"`, '"upstream":"api.evil.example"');
    const tamperOk =
      tampered !== json &&
      cryptoVerify(
        'sha256',
        Buffer.from(tampered, 'utf8'),
        sigOpts,
        Buffer.from(sig.sig, 'base64'),
      );
    if (!tamperOk) pass('rewriting the upstream breaks the signature (checked, not claimed)');
    else fail('a tampered receipt still verified — the signature proves nothing');
  }

  console.log('\n3. what this does and does not establish');
  console.log(`   The enclave's own TLS validated against ${receipt.upstream}.`);
  if (receipt.upstream_selects_provider) {
    console.log('   This is an OpenRouter route: OpenRouter picks the underlying');
    console.log('   provider itself, so the guarantee stops at its door.');
  } else {
    console.log('   This is a direct route, so the named host served the request.');
  }
  console.log('   NOT established here: that this receipt belongs to one particular');
  console.log('   request — it names no request id, time or response.');

  console.log(failures ? `\nFAILED (${failures})\n` : '\nAll checks passed.\n');
  exit(failures ? 1 : 0);
};

main().catch((e) => {
  console.error(`\nerror: ${e.message}\n`);
  exit(2);
});
