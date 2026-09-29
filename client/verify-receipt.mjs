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
// * **That a v1 receipt belongs to a particular request.** A v1 receipt
//   carries no request id or time, so it shows that the enclave signed that
//   routing statement, not which exchange it was signed for. A v2 receipt
//   names the request: a live run sends a random `x-request-id` and requires
//   it back under the signature, and `--request-id` requires one of a saved
//   stream. Neither version covers the CONTENT of the answer.
// * **That the served model is what the receipt says.** `served_model` is what
//   the upstream's answer named: the upstream's claim, signed as having been
//   made.
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
//   node client/verify-receipt.mjs --credit-id <id>       # authenticate with a credit id
//   node client/verify-receipt.mjs --no-stream            # the header receipt of a JSON response
//   node client/verify-receipt.mjs --request-id <id>      # with --sse: the id the receipt must name
//   node client/verify-receipt.mjs --connect <ip>         # reach --host at this address
//
// A host whose certificate no public CA issued (the dev enclave) needs
// NODE_TLS_REJECT_UNAUTHORIZED=0. The attestation is what authenticates the
// endpoint here either way: the key is taken from the connection and must be
// the one the signed document commits to.

import { argv, exit } from 'node:process';
import { readFileSync } from 'node:fs';
import { X509Certificate, createHash, createPublicKey, randomBytes, verify as cryptoVerify, constants } from 'node:crypto';
import https from 'node:https';
import { verifyAttestation } from './browser-verify.mjs';

const RECEIPT_PREFIX = ': ppq-routing-receipt ';
const RECEIPT_SIG_PREFIX = ': ppq-routing-receipt-sig ';
const RECEIPT_HEADER = 'ppq-routing-receipt';
const RECEIPT_SIG_HEADER = 'ppq-routing-receipt-sig';
/** How far the receipt's clock may be from this machine's, either way. */
const MAX_CLOCK_DISTANCE_MS = 10 * 60 * 1000;

function arg(name, fallback = undefined) {
  const i = argv.indexOf(`--${name}`);
  return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
}

const HOST = arg('host', 'enclave.ppq.ai');
const MODEL = arg('model', 'anthropic/claude-sonnet-5');
const API_KEY = arg('key');
const SSE_FILE = arg('sse');
const WANT_PCR0 = arg('pcr0');
const CREDIT_ID = arg('credit-id');
const CONNECT = arg('connect');
const NO_STREAM = argv.includes('--no-stream');
const WANT_REQUEST_ID = arg('request-id');
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

/**
 * One HTTPS exchange with the enclave, returning the SPKI of the certificate
 * the connection was served along with the response.
 */
function exchange(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: CONNECT || HOST, servername: HOST, path, method, agent: false, headers: { host: HOST, ...headers } },
      (res) => {
        const peer = res.socket.getPeerCertificate();
        const spkiDer = peer?.raw
          ? new X509Certificate(peer.raw).publicKey.export({ type: 'spki', format: 'der' })
          : null;
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), spkiDer }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.setTimeout(120_000, () => req.destroy(new Error('timed out')));
    req.end(body);
  });
}

async function fetchAttestation(nonceHex) {
  const res = await exchange('GET', `/attestation?nonce=${nonceHex}`);
  if (res.status !== 200) throw new Error(`/attestation returned ${res.status}`);
  return { ...JSON.parse(res.text), servedSpkiDer: res.spkiDer };
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

/** A live request carrying an id only this run knows. */
async function fetchAnswer(requestId) {
  const headers = { 'content-type': 'application/json', 'x-request-id': requestId };
  if (API_KEY) headers.authorization = `Bearer ${API_KEY}`;
  if (CREDIT_ID) headers['x-credit-id'] = CREDIT_ID;
  const body = JSON.stringify({
    model: MODEL,
    stream: !NO_STREAM,
    max_tokens: 12,
    messages: [{ role: 'user', content: 'Say OK.' }],
  });
  const res = await exchange('POST', '/v1/chat/completions', {
    headers: { ...headers, 'content-length': Buffer.byteLength(body) },
    body,
  });
  // Where the receipt is follows the RESPONSE, not the request: an upstream
  // that refuses a streamed request answers in JSON, and that carries headers.
  const found = res.headers[RECEIPT_HEADER] || res.text.includes(RECEIPT_PREFIX);
  if (!found) {
    throw new Error(
      `no receipt in the response (HTTP ${res.status}). ` +
        (API_KEY || CREDIT_ID ? 'Body: ' : 'Try --key <sk-...> or --credit-id <id>. Body: ') +
        res.text.slice(0, 200),
    );
  }
  return res;
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

/** The header form: the receipt is the base64 of the bytes that were signed. */
function extractFromHeaders(headers) {
  return {
    json: Buffer.from(headers[RECEIPT_HEADER], 'base64').toString('utf8'),
    sig: headers[RECEIPT_SIG_HEADER] ? JSON.parse(headers[RECEIPT_SIG_HEADER]) : null,
  };
}

const main = async () => {
  console.log(`\nAttested routing receipt — ${HOST}\n`);

  const nonceHex = randomBytes(32).toString('hex');
  const att = await fetchAttestation(nonceHex);
  const spkiDer = Buffer.from(att.cert_spki_der, 'base64');
  if (att.servedSpkiDer && !att.servedSpkiDer.equals(spkiDer)) {
    fail('the key the response advertises is not the key this connection was served');
  }

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
  const sentRequestId = SSE_FILE ? WANT_REQUEST_ID : `verify-${randomBytes(12).toString('hex')}`;
  let extracted;
  if (SSE_FILE) {
    extracted = extract(readFileSync(SSE_FILE, 'utf8'));
  } else {
    const answer = await fetchAnswer(sentRequestId);
    extracted = answer.headers[RECEIPT_HEADER] ? extractFromHeaders(answer.headers) : extract(answer.text);
    console.log(`   carried in      : ${answer.headers[RECEIPT_HEADER] ? 'response headers' : 'the event stream'} (HTTP ${answer.status})`);
    if (answer.spkiDer && !answer.spkiDer.equals(spkiDer)) {
      fail('the request was served a different key from the one that was attested');
    }
  }
  const { json, sig } = extracted;
  const receipt = JSON.parse(json);

  console.log(`   version         : ${receipt.v}`);
  console.log(`   request id      : ${receipt.request_id ?? '(none)'}${receipt.request_id_source ? ` (chosen by the ${receipt.request_id_source})` : ''}`);
  console.log(`   issued at       : ${receipt.issued_at ?? '(none)'}`);
  console.log(`   served model    : ${receipt.served_model ?? '(not known when the receipt was written)'}`);
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

  console.log('\n3. which request the receipt is for');
  if (!(receipt.v >= 2)) {
    // Not a failure while enclaves that write v1 are still in service: the
    // receipt is genuine, it just says less. Make this a failure once no
    // accepted measurement writes v1.
    console.log(`  ! this is a v${receipt.v} receipt: it names no request, so it cannot be tied to one`);
  } else {
    if (!sentRequestId) {
      console.log('   no --request-id given: the id above was not checked against one you sent');
    } else if (receipt.request_id === sentRequestId && receipt.request_id_source === 'client') {
      pass(`it names the request id ${SSE_FILE ? 'you gave' : 'this run sent'} (${sentRequestId})`);
    } else {
      fail(`it names ${receipt.request_id ?? 'no request id'}, not ${sentRequestId} — this receipt is for another request`);
    }
    const distance = Math.abs(Date.parse(receipt.issued_at) - Date.now());
    if (SSE_FILE) {
      console.log('   saved stream: the time above was not checked against the clock');
    } else if (distance <= MAX_CLOCK_DISTANCE_MS) {
      pass(`it was issued ${Math.round(distance / 1000)} s from this machine's clock`);
    } else {
      fail(`it was issued at ${receipt.issued_at}, not now`);
    }
  }

  console.log('\n4. what this does and does not establish');
  console.log(`   The enclave's own TLS validated against ${receipt.upstream}.`);
  if (receipt.upstream_selects_provider) {
    console.log('   This is an OpenRouter route: OpenRouter picks the underlying');
    console.log('   provider itself, so the guarantee stops at its door.');
  } else {
    console.log('   This is a direct route, so the named host served the request.');
  }
  console.log('   NOT established here: anything about the content of the answer, or that');
  console.log('   the served model is more than what the upstream said it was.');

  console.log(failures ? `\nFAILED (${failures})\n` : '\nAll checks passed.\n');
  exit(failures ? 1 : 0);
};

main().catch((e) => {
  console.error(`\nerror: ${e.message}\n`);
  exit(2);
});
