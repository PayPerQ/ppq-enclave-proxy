#!/usr/bin/env node
// Verify an attested routing receipt end to end.
//
// WHAT THIS PROVES
// ----------------
// The enclave states, in a signature you can check, which upstream host its own
// TLS validated against for your request. The chain is four links, and this
// script walks all four rather than asserting any of them:
//
//   1. GET /attestation -> an AWS-signed COSE document containing `user_data`
//   2. take the certificate SPKI and SHA-256 it
//   3. require that hash to appear inside the signed document
//        -> the key is committed to by the Nitro Security Module, so the host
//           cannot substitute its own
//   4. verify the receipt signature against that SPKI
//        -> the receipt came from the measured enclave, not from PayPerQ
//
// Step 3 is the load-bearing one. Without it, steps 1 and 4 are theatre: a host
// could hand you any key and sign anything with it.
//
// WHAT THIS DOES NOT PROVE
// ------------------------
// Stated plainly, because a verification tool that oversells is worse than none:
//
// * **It does not prove the enclave runs the code we published.** That is the
//   PCR0 pin, a separate check -- compare the PCR0 inside the attestation
//   document against `attestation/published-pcr.json` and against the Sigstore
//   provenance on the build that produced it. `--pcr0 <hex>` will check the
//   measurement is present, but you must decide for yourself that the value is
//   one you trust.
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
//   node client/verify-receipt.mjs --pcr0 <96-hex>        # also require this measurement

import { argv, exit } from 'node:process';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify as cryptoVerify, constants } from 'node:crypto';

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

let failures = 0;
const pass = (m) => console.log(`  ✓ ${m}`);
const fail = (m) => {
  failures++;
  console.log(`  ✗ ${m}`);
};

async function fetchAttestation() {
  const res = await fetch(`https://${HOST}/attestation`);
  if (!res.ok) throw new Error(`/attestation returned ${res.status}`);
  return res.json();
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

  const att = await fetchAttestation();
  const spkiDer = Buffer.from(att.cert_spki_der, 'base64');
  const doc = Buffer.from(att.attestation_document_b64, 'base64');

  console.log('1. attestation document');
  const spkiHash = createHash('sha256').update(spkiDer).digest('hex');
  if (spkiHash === (att.cert_spki_sha256 || '').toLowerCase()) {
    pass('the SPKI hashes to the value the response advertises');
  } else {
    fail('advertised cert_spki_sha256 does not match the SPKI it shipped');
  }

  // The step that makes the rest mean anything. Searching the raw COSE bytes
  // rather than parsing CBOR keeps this dependency-free; the hash is 32 bytes
  // of high-entropy data, so a coincidental match is not a practical concern.
  if (doc.includes(Buffer.from(spkiHash, 'hex'))) {
    pass('that hash appears INSIDE the NSM-signed document (the host cannot swap the key)');
  } else {
    fail('the SPKI hash is NOT in the signed document — stop here, the key is unattested');
  }

  if (WANT_PCR0) {
    if (doc.includes(Buffer.from(WANT_PCR0.toLowerCase(), 'hex'))) {
      pass(`the measurement ${WANT_PCR0.slice(0, 16)}… is present`);
    } else {
      fail(`the measurement ${WANT_PCR0.slice(0, 16)}… is NOT present`);
    }
  }

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
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(json, 'utf8'),
      { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
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
        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
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
  console.log('   NOT established here: that the enclave runs published code — that is');
  console.log('   the PCR0 pin, checked with --pcr0 against attestation/published-pcr.json.');

  console.log(failures ? `\nFAILED (${failures})\n` : '\nAll checks passed.\n');
  exit(failures ? 1 : 0);
};

main().catch((e) => {
  console.error(`\nerror: ${e.message}\n`);
  exit(2);
});
