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

/**
 * Bumped when the shape changes, so a consumer can refuse what it cannot read.
 *
 * v2 adds `request_id`, `request_id_source`, `issued_at` and `served_model`.
 * A v1 receipt named a route and nothing else, so two requests for the same
 * model produced byte-identical receipts and a signature lifted from one
 * verified for the other (measured on production, 2026-09-29). A receipt has
 * to say WHICH exchange it is about to be a receipt for anything.
 */
export const RECEIPT_VERSION = 2;

/** The marker a client greps for. Stable; the payload after it is JSON. */
export const RECEIPT_PREFIX = ': ppq-routing-receipt ';

/**
 * A request id as it may appear in a receipt: printable ASCII, bounded.
 *
 * The caller's `x-request-id` is echoed only back to the caller, so this is
 * not about who may read it. It is about the two places the value lands: an
 * HTTP header, where a byte outside Latin-1 throws, and a signed statement,
 * which should not carry an unbounded caller-chosen string.
 */
const REQUEST_ID_RE = /^[\x20-\x7e]{1,128}$/;

/** A model id as an upstream may report it; the shape cost.mjs captures. */
const SERVED_MODEL_RE = /^[a-zA-Z0-9._:/@~-]{1,96}$/;

/**
 * Build the receipt object.
 *
 * @param {object} o
 * @param {string} [o.requestId]     this exchange's id: the caller's
 *        `x-request-id` when one was sent, else the id minted here
 * @param {boolean} [o.requestIdFromClient] whether the caller chose that id.
 *        Only a caller-chosen id BINDS: the caller sends a value nobody else
 *        knows and requires it back under the signature. An id minted here
 *        distinguishes receipts from one another and proves nothing to a
 *        caller who never saw it anywhere else.
 * @param {Date} [o.issuedAt]        when the enclave wrote the receipt
 * @param {string} [o.servedModel]   the model id the upstream's answer named,
 *        when it had named one by the time the receipt was written
 * @param {string} o.requestedModel  what the client asked for
 * @param {object} o.spec            the chosen upstream spec (from upstreams.mjs)
 * @param {number} o.statusCode      upstream status
 * @param {Array<{provider: string, reason: string, field?: string}>} [o.skipped]
 *        candidates the enclave declined BEFORE contacting them, and why
 * @param {Array<{provider: string, status?: number}>} [o.failed]
 *        candidates that were contacted and did not serve
 */
export function buildReceipt({
  requestedModel,
  spec,
  statusCode,
  skipped = [],
  failed = [],
  requestId,
  requestIdFromClient = false,
  issuedAt,
  servedModel,
}) {
  const direct = Boolean(spec?.isDirect);
  const boundId = typeof requestId === 'string' && REQUEST_ID_RE.test(requestId) ? requestId : null;
  return {
    v: RECEIPT_VERSION,
    // Which exchange this is. An id that does not fit the shape is dropped,
    // and its source with it, rather than signed in some altered form the
    // caller would not recognise.
    request_id: boundId,
    request_id_source: boundId ? (requestIdFromClient ? 'client' : 'enclave') : null,
    // The enclave's clock, which the parent instance supplies: good for
    // ordering and for rejecting a receipt from another day, not a timestamp
    // to the second.
    issued_at: issuedAt instanceof Date && !Number.isNaN(issuedAt.getTime()) ? issuedAt.toISOString() : null,
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
    // What the upstream's ANSWER said served it: the upstream's claim, stated
    // under our signature so that it is at least undeniable that the claim was
    // made. `upstream_model` is what was sent; this is what came back. Null
    // when the answer had not named a model by the time this was written,
    // which on a JSON response is always (the receipt rides the headers).
    served_model: typeof servedModel === 'string' && SERVED_MODEL_RE.test(servedModel) ? servedModel : null,
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

/** RSASSA-PSS over SHA-256, salt length = digest length: the label for an RSA key. */
export const RECEIPT_SIG_ALG = 'RSA-PSS-SHA256';
/** ECDSA over SHA-256, DER-encoded signature: the label for an EC key. */
export const RECEIPT_SIG_ALG_EC = 'ECDSA-SHA256';

/**
 * The label follows the KEY, because the key follows the served certificate:
 * ACME issues P-256 and, since #195, so does boot.sh, so there is no RSA key
 * in the process any more; a fixed RSA label would be false on every receipt.
 * A key that cannot say (a PEM string) is treated as RSA, the legacy shape.
 */
export function receiptSigAlg(key) {
  return key?.asymmetricKeyType === 'ec' ? RECEIPT_SIG_ALG_EC : RECEIPT_SIG_ALG;
}

/**
 * sign()/verify() options for a key. Node ignores the RSA-PSS parameters for
 * an EC key, so passing them "works" -- being explicit is what keeps a reader,
 * and any verifier written from this file, from believing PSS is in use.
 */
export function receiptSigOptions(key) {
  return key?.asymmetricKeyType === 'ec'
    ? { key, dsaEncoding: 'der' }
    : { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
}

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
  return cryptoSign('sha256', Buffer.from(receiptJson, 'utf8'), receiptSigOptions(privateKey)).toString('base64');
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
    const meta = JSON.stringify({ alg: receiptSigAlg(privateKey), over: 'receipt_json_utf8', sig });
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

// ── Header receipts: responses that are not event streams (v2) ───────────────
//
// A JSON body cannot carry a comment line, so until v2 a non-streaming
// response carried no receipt at all. It rides two response headers instead.
//
// The objection at the top of this file -- a header is forgeable by the host --
// is an objection to an UNSIGNED header. A signed one can be stripped by the
// host and cannot be altered or invented, and a stripped receipt is visible as
// its absence. That is why the header form is never emitted unsigned: with no
// key there are no headers, where the SSE form still writes its receipt line
// (it rides inside the EHBP seal; these headers do not).
//
// The receipt value is the base64 of the exact JSON bytes the signature is
// over. Base64 because `requested_model` is the caller's string and a header
// value outside Latin-1 throws in writeHead -- the receipt must never be why a
// response fails.

export const RECEIPT_HEADER = 'ppq-routing-receipt';
export const RECEIPT_SIG_HEADER = 'ppq-routing-receipt-sig';

/**
 * The two headers for a response that cannot carry the SSE form, or null:
 * when the response is an event stream (it carries the comment lines), when
 * there is no key, or when signing fails.
 */
export function signedReceiptHeaders(contentType, receipt, privateKey) {
  if (canCarryReceipt(contentType) || !privateKey) return null;
  try {
    const json = JSON.stringify(receipt);
    const sig = signReceiptJson(json, privateKey);
    return {
      [RECEIPT_HEADER]: Buffer.from(json, 'utf8').toString('base64'),
      [RECEIPT_SIG_HEADER]: JSON.stringify({
        alg: receiptSigAlg(privateKey),
        // Names what the signature covers: the decoded bytes, not the base64.
        over: 'receipt_json_utf8',
        sig,
      }),
    };
  } catch {
    return null;
  }
}

// ── Where in an event stream the receipt goes (v2) ───────────────────────────
//
// v1 wrote the receipt before any upstream byte, which was always a safe place
// and always too early to know what the answer would say served it. v2 writes
// it ahead of the first FRAME, once that frame's model is known.
//
// Two things make that harder than it sounds, and both were found by driving
// the server rather than by reading it:
//
//   * a frame arrives in pieces. Deciding on the first piece writes the
//     receipt before the model has been read; deciding on the second writes it
//     into the middle of a line and corrupts a frame the client will parse.
//   * an upstream opens with keep-alive comments, which must keep flowing
//     while nothing else does.
//
// So until the receipt is written, comment lines pass as they complete and the
// first frame is HELD until it names its model or is complete, then released
// behind the receipt. After that the gate is open and passes everything.

const LF = 0x0a;
const CR = 0x0d;
const COLON = 0x3a;

/** Placeholder in a gate's output for "the receipt goes here". */
export const RECEIPT_HERE = Symbol('receipt');

/**
 * A partial first frame is not held past this. Past it the receipt is written
 * without the served model rather than the stream stalled for one.
 */
const MAX_HELD_BYTES = 64 * 1024;

/**
 * Offset of the first line that is a field (`data:`, `event:`) rather than a
 * comment or a blank line, or -1. A line is judged by its first byte, so a
 * line that has only begun to arrive can already be judged.
 */
function firstFieldLine(buf) {
  let start = 0;
  while (start < buf.length) {
    const first = buf[start];
    if (first !== COLON && first !== LF && first !== CR) return start;
    const end = buf.indexOf(LF, start);
    if (end === -1) return -1;
    start = end + 1;
  }
  return -1;
}

/** Whether these bytes contain the blank line that ends an SSE event. */
function hasEventEnd(buf) {
  return buf.includes('\n\n') || buf.includes('\r\n\r\n');
}

export class ReceiptGate {
  /**
   * @param {object} [o]
   * @param {boolean} [o.carries] false for a response that is not an event
   *        stream: there is no receipt to place and nothing is ever held
   */
  constructor({ carries = true, maxHeld = MAX_HELD_BYTES } = {}) {
    this.open = !carries;
    this.written = !carries;
    this.held = Buffer.alloc(0);
    this.maxHeld = maxHeld;
  }

  /**
   * Bytes on their way to the client. Returns what to write now, in order:
   * Buffers, with RECEIPT_HERE where the receipt goes.
   *
   * @param {Buffer} out         what the rewriter released
   * @param {*} modelKnown       truthy once the answer has named its model
   */
  feed(out, modelKnown) {
    if (this.open) return out && out.length > 0 ? [out] : [];
    const all = out && out.length > 0 ? Buffer.concat([this.held, out]) : this.held;
    const frameAt = firstFieldLine(all);

    if (frameAt === -1) {
      // Comments and blank lines only. Complete lines pass; a line still
      // arriving waits, since it cannot be judged until it has a first byte
      // and must not be followed by a receipt until it has a last one.
      if (all.length > this.maxHeld) return this._giveUp(all);
      const cut = all.lastIndexOf(LF) + 1;
      this.held = all.subarray(cut);
      return cut > 0 ? [all.subarray(0, cut)] : [];
    }

    const before = all.subarray(0, frameAt);
    const frame = all.subarray(frameAt);
    if (modelKnown || hasEventEnd(frame) || all.length > this.maxHeld) {
      this.open = true;
      this.written = true;
      this.held = Buffer.alloc(0);
      return [before, RECEIPT_HERE, frame].filter((part) => part === RECEIPT_HERE || part.length > 0);
    }
    this.held = frame;
    return before.length > 0 ? [before] : [];
  }

  /** A comment line that never ended: let it through, place the receipt at the end. */
  _giveUp(all) {
    this.open = true;
    this.held = Buffer.alloc(0);
    this.stoppedMidLine = true;
    return [all];
  }

  /**
   * The stream is over. Whatever is still held goes out, with the receipt if
   * it has not been written: ahead of a frame that never completed, behind a
   * comment that never did (and behind the blank line that ends it).
   */
  finish() {
    const held = this.held;
    this.held = Buffer.alloc(0);
    this.open = true;
    if (this.written) return held.length > 0 ? [held] : [];
    this.written = true;
    const blank = Buffer.from('\n\n', 'utf8');
    if (this.stoppedMidLine) return [blank, RECEIPT_HERE];
    if (held.length === 0) return [RECEIPT_HERE];
    return firstFieldLine(held) === 0 ? [RECEIPT_HERE, held] : [held, blank, RECEIPT_HERE];
  }
}
