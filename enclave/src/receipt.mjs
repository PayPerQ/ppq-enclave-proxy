// Attested routing receipt — the enclave stating where a request actually went.
//
// WHY
// ---
// Attestation proves the enclave runs published code. It does NOT prove the
// request went where the user asked, because the enclave does not choose the
// upstream: horse-power does, at /enclave/authorize, and horse-power is a
// normal web app with no measurement attached. `upstreams.mjs` builds the
// request from hp's candidate — `servername`, `path` and the upstream model all
// come from that directive — and there is no in-enclave allowlist to check it
// against. So provider or model substitution decided in hp is invisible.
//
// Before this, the enclave told the client nothing at all about the upstream.
// The only `provider` a user ever saw came from OpenRouter's own response
// frames, which is OpenRouter's claim rather than ours, and is absent entirely
// on direct paths — the rewriter deliberately hides the wire model id behind
// the public slug, so a direct Anthropic request looked identical to an
// OpenRouter one.
//
// This does not PREVENT substitution. It makes it undeniable: the statement
// comes from measured code, so "the enclave says it went to api.anthropic.com"
// is checkable against source anyone can read. Same shift Certificate
// Transparency makes — not stopping a bad act, ending its deniability.
// Prevention is issue #58 phase 3, a family-level map measured into PCR0.
//
// WHY AN SSE COMMENT
// ------------------
// A response header would be worthless here: nginx terminates TLS on the public
// path, so the parent can rewrite headers freely — forgeable by exactly the
// party the receipt exists to constrain. Inside the body it rides the EHBP seal
// (and, once #52 lands, in-enclave TLS), so the host cannot touch it.
//
// SSE comment lines are ignored by every SSE parser and by the OpenAI SDKs, and
// this server already emits `: PPQ.AI PROCESSING` comments, so the mechanism is
// proven against real clients rather than assumed.
//
// CONTENT-FREE, like everything else that leaves here: routing facts only,
// never anything derived from the prompt or the completion.

import { constants, sign as cryptoSign } from 'node:crypto';

/** Bumped when the shape changes, so a consumer can refuse what it cannot read. */
export const RECEIPT_VERSION = 1;

/** The marker a client greps for. Stable; the payload after it is JSON. */
export const RECEIPT_PREFIX = ': ppq-routing-receipt ';

/**
 * Build the receipt object.
 *
 * @param {object} o
 * @param {string} o.requestedModel  what the client asked for
 * @param {object} o.spec            the chosen upstream spec (from upstreams.mjs)
 * @param {number} o.statusCode      upstream status
 * @param {Array<{provider: string, reason: string, field?: string}>} [o.skipped]
 *        candidates the enclave declined BEFORE contacting them, and why
 * @param {Array<{provider: string, status?: number}>} [o.failed]
 *        candidates that were contacted and did not serve
 */
export function buildReceipt({ requestedModel, spec, statusCode, skipped = [], failed = [] }) {
  const direct = Boolean(spec?.isDirect);
  return {
    v: RECEIPT_VERSION,
    // What the client asked for, echoed so the receipt stands alone rather than
    // only making sense next to the request.
    requested_model: requestedModel || null,
    // The hostname the enclave's TLS actually validated against. This is the
    // load-bearing field: TLS is terminated inside the enclave against this
    // name, so the parent cannot redirect it elsewhere without failing the
    // handshake. It is also the field hp controls, which is exactly why it is
    // worth stating.
    upstream: spec?.opts?.servername || null,
    // The model id put on the wire, which for a direct provider differs from
    // the public slug the response is rewritten to show.
    upstream_model: spec?.upstreamModel || null,
    route: direct ? 'direct' : 'openrouter',
    provider: direct ? spec?.provider || null : 'openrouter',
    upstream_status: typeof statusCode === 'number' ? statusCode : null,
    // Why the enclave did not use the candidates ahead of this one. Without
    // these, "it went to OpenRouter" is unexplained and looks arbitrary.
    skipped: skipped.map((s) => ({
      provider: s.provider || null,
      reason: s.reason || null,
      ...(s.field ? { field: s.field } : {}),
    })),
    failed: failed.map((f) => ({
      provider: f.provider || null,
      ...(typeof f.status === 'number' ? { status: f.status } : {}),
    })),
    // Stated rather than implied: for an OpenRouter route the guarantee stops
    // at OpenRouter's door, since OR picks the underlying provider itself.
    // A receipt that let a reader forget that would be worse than none.
    upstream_selects_provider: !direct,
  };
}

/**
 * Serialise as an SSE comment line.
 *
 * Newlines are stripped from the JSON (there are none in compact form, but a
 * stray one would terminate the comment and inject a frame into the stream).
 */
export function formatReceiptLine(receipt) {
  const json = JSON.stringify(receipt).replace(/[\r\n]/g, ' ');
  return `${RECEIPT_PREFIX}${json}\n\n`;
}

/**
 * Whether a receipt can be safely emitted into this response.
 *
 * ONLY event-streams. A leading comment line prepended to an
 * `application/json` body would corrupt it — the client would fail to parse a
 * response that was otherwise fine, which is a far worse outcome than an
 * absent receipt.
 */
export function canCarryReceipt(contentType) {
  return typeof contentType === 'string' && contentType.includes('text/event-stream');
}

/** Convenience: the bytes to write, or null when this response cannot carry one. */
export function receiptBytes(contentType, receipt) {
  if (!canCarryReceipt(contentType)) return null;
  return Buffer.from(formatReceiptLine(receipt), 'utf8');
}

// ── Signing (#58 phase 2) ────────────────────────────────────────────────────
//
// WHY THIS NEEDS NO NEW ATTESTED KEY
// ----------------------------------
// The attestation document already commits to `user_data = SHA-256(TLS cert
// SPKI)`, and that keypair is generated inside the enclave by boot.sh and never
// leaves it. So signing the receipt with the TLS private key makes the
// signature verifiable against a commitment that already exists:
//
//   1. fetch /attestation -> the AWS-signed COSE document, containing user_data
//   2. obtain the cert SPKI -- from the TLS peer certificate (programmatic
//      clients) or from `cert_spki_der` in the attestation response (browsers,
//      which cannot read a peer certificate)
//   3. SHA-256 it and require it to equal user_data -> the SPKI is attested
//   4. verify this signature against that SPKI -> the receipt came from the
//      measured enclave
//
// Step 3 is what stops the host substituting its own key in step 2: the hash
// must match a value inside a document signed by the Nitro Security Module.
//
// WHAT SIGNING BUYS OVER AN UNSIGNED RECEIPT
// ------------------------------------------
// An unsigned receipt is only trustworthy inside a channel the host cannot
// touch -- today that means the EHBP seal, so the web app can rely on it and a
// plain HTTPS client cannot. A signed receipt is trustworthy through ANY hop,
// including nginx, and remains checkable after the fact once written down.
// That is the difference between a log line and a receipt.

/** RSASSA-PSS over SHA-256, salt length = digest length. */
export const RECEIPT_SIG_ALG = 'RSA-PSS-SHA256';

/** The marker for the signature line, emitted directly after the receipt. */
export const RECEIPT_SIG_PREFIX = ': ppq-routing-receipt-sig ';

/**
 * Sign the EXACT receipt bytes.
 *
 * Signing the literal serialised JSON rather than a canonicalisation of the
 * object removes any question of field order or whitespace: the verifier checks
 * the signature over the bytes it actually received, so there is nothing to
 * agree on and nothing to get subtly wrong.
 */
export function signReceiptJson(receiptJson, privateKey) {
  return cryptoSign('sha256', Buffer.from(receiptJson, 'utf8'), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString('base64');
}

/**
 * The receipt line plus its signature line.
 *
 * Returns just the receipt when no key is available, rather than failing: an
 * unsigned receipt is still useful inside the EHBP seal, and a signing problem
 * must never be why a request loses its answer.
 */
export function formatSignedReceiptLines(receipt, privateKey) {
  const json = JSON.stringify(receipt).replace(/[\r\n]/g, ' ');
  const receiptLine = `${RECEIPT_PREFIX}${json}\n\n`;
  if (!privateKey) return receiptLine;
  try {
    const sig = signReceiptJson(json, privateKey);
    // `over` names exactly what the signature covers, so a verifier does not
    // have to guess whether the marker or the newlines are included.
    const meta = JSON.stringify({ alg: RECEIPT_SIG_ALG, over: 'receipt_json_utf8', sig });
    return `${receiptLine}${RECEIPT_SIG_PREFIX}${meta}\n\n`;
  } catch {
    return receiptLine;
  }
}

/** Bytes to write, or null when this response cannot carry a receipt. */
export function signedReceiptBytes(contentType, receipt, privateKey) {
  if (!canCarryReceipt(contentType)) return null;
  return Buffer.from(formatSignedReceiptLines(receipt, privateKey), 'utf8');
}
