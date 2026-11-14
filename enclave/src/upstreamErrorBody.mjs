/**
 * Sanitizer for a passed-through upstream ERROR body.
 *
 * OpenRouter is the terminal candidate and its answer is piped regardless of
 * status, so a 4xx/5xx body used to reach the client byte-for-byte. That body
 * carries a top-level `user_id`: OpenRouter's id for PayPerQ's organisation
 * (`org_…`), one constant value on every request from every host, readable by
 * any client with one bad model id. It can also carry `error.metadata.
 * provider_name` (the provider behind the model), links to openrouter.ai and
 * the name itself — everything the product hides behind "AI Provider".
 *
 * The enclave is content-free by design, but an upstream error body is not
 * query content: deleting known keys and rewording a vendor name is within
 * that rule. `error.message` and `error.code` are kept (clients act on them),
 * as is `error.metadata.raw`, the provider's own diagnostic — for a
 * provider-side failure it is usually the only text that says what went
 * wrong. horse-power's `sanitizeErrorResponse` (utils/errors.ts) does the
 * same on the direct path; the two must agree.
 */
import { Transform } from 'node:stream';

/** An error body larger than this is not an error body; it is replaced. */
export const MAX_ERROR_BODY_BYTES = 256 * 1024;

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Pass 1, in place: drop the fields that name the upstream or our account with it. */
export function stripUpstreamIdentity(parsed) {
  if (!isPlainObject(parsed)) return parsed;
  delete parsed.user_id;
  // OpenRouter nests `metadata` under `error`; a top-level one is handled too
  // so a shape change upstream cannot quietly reopen the leak.
  for (const holder of [parsed, parsed.error]) {
    if (isPlainObject(holder) && isPlainObject(holder.metadata)) {
      delete holder.metadata.provider_name;
    }
  }
  return parsed;
}

/** The wording pass over one string, mirroring horse-power: links, the docs pointer, the name. */
export function sanitizeUpstreamWording(text) {
  let s = text.replace(/https?:\/\/(www\.)?openrouter\.ai[^\s"')\]]*[^\s"')\],.]*/gi, '');
  s = s.replace(/Please refer to our docs:/gi, '');
  s = s.replace(/openrouter/gi, 'AI Provider');
  // Spaces and tabs only: this runs on a real string, where `\s` would also
  // collapse the newlines of a multi-line provider diagnostic.
  s = s.replace(/[ \t]{2,}/g, ' ');
  s = s.replace(/[ \t]+([,.)])/, '$1');
  return s;
}

/** Pass 2, in place: the wording pass over every string value. */
function sanitizeWordingDeep(v) {
  if (typeof v === 'string') return sanitizeUpstreamWording(v);
  if (Array.isArray(v)) return v.map(sanitizeWordingDeep);
  if (isPlainObject(v)) {
    for (const k of Object.keys(v)) v[k] = sanitizeWordingDeep(v[k]);
  }
  return v;
}

/**
 * Both passes. The wording pass runs on the PARSED string values, never on
 * the serialized text: run over serialized JSON, the link regex eats the
 * backslash of an escape that follows a URL (`…/docs\"` → `"`) and the client
 * receives invalid JSON, and an escaped newline after a URL was swallowed with
 * the next word (CodeRabbit on #245). A body that is not JSON at all gets the
 * wording pass over its text, which is all that can be done with it.
 */
export function sanitizeUpstreamErrorBody(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return sanitizeUpstreamWording(text);
  }
  return JSON.stringify(sanitizeWordingDeep(stripUpstreamIdentity(parsed)));
}

// ─── The provider refusing OUR account ───────────────────────────────────────
//
// A provider answers an unpaid bill, an empty prepaid balance or a spend cap on
// our key with 402 (or a 4xx naming billing). Relayed as it came, that reads
// to the customer as "your balance is too low": on this platform 402 is the
// customer's own balance (hp's authorize). So the answer is replaced with a
// retryable 503 that says the fault is ours, and the report tells hp, which
// alerts. horse-power's services/providerAccountAlert.ts holds the same
// predicate for its own paths; the two must agree.

/**
 * Billing wording in a provider's error body. Phrases, not single words:
 * `quota` alone is also how a rate limit is described. "You exceeded your
 * current quota" is left out on purpose: Gemini says exactly that for an
 * ordinary rate limit. So is a bare "account suspended": a provider says that
 * for a content-policy suspension too, which is not a billing incident.
 */
const BILLING_MARKERS = [
  /insufficient[_ ]quota/i,
  /billing[_ ]error/i,
  /billing[_ ]not[_ ]active/i,
  /billing[_ ]hard[_ ]limit/i,
  /credit balance is too low/i,
  /insufficient[_ ](?:credits?|funds|balance)/i,
  /payment[_ ]required/i,
  /requires more credits/i,
  /key limit exceeded/i,
  /spending limit/i,
  /(?:unpaid|overdue|outstanding) (?:invoice|balance)/i,
];

/** How much of an error body is searched. A provider's error envelope is short. */
export const MARKER_SCAN_CHARS = 2000;

/** True when a provider's error text names billing on our account. */
export function namesProviderBilling(text) {
  if (typeof text !== 'string' || text === '') return false;
  const head = text.slice(0, MARKER_SCAN_CHARS);
  return BILLING_MARKERS.some((re) => re.test(head));
}

/**
 * True when an UPSTREAM's answer is about PayPerQ's account with it: any 402
 * (the customer's credential never reaches a provider), or another 4xx whose
 * error text names billing. A bare 401/403 is not taken: 403 is also how a
 * provider refuses moderated input. Never call this with hp's own status.
 */
export function isProviderAccountError(statusCode, text) {
  if (statusCode === 402) return true;
  if (!Number.isInteger(statusCode) || statusCode < 400 || statusCode > 499) return false;
  return namesProviderBilling(text);
}

/** The status the client is served instead of the provider's. Retryable for SDKs, and not 402. */
export const PROVIDER_ACCOUNT_ERROR_STATUS = 503;
export const PROVIDER_ACCOUNT_ERROR_CODE = 'provider_account_error';
export const PROVIDER_ACCOUNT_ERROR_MESSAGE =
  "This model's AI provider is temporarily unavailable because of an issue on our side. " +
  'It is not a problem with your account or your balance. Please try again later or use a different model.';
/** The error report's `reason` for it (the sink's token shape). */
export const PROVIDER_ACCOUNT_REASON = 'PROVIDER_ACCOUNT';

/** The chat-dialect body served instead of the provider's own. */
export function providerAccountErrorBody() {
  return JSON.stringify({
    error: { message: PROVIDER_ACCOUNT_ERROR_MESSAGE, type: 'upstream_error', code: PROVIDER_ACCOUNT_ERROR_CODE },
  });
}

/**
 * The same answer in a relay's dialect: its own error envelope for a 503 (a
 * dialect object with `errorBody`), carrying the same `code` the chat body
 * does so the cause is recognisable on every route.
 */
export function providerAccountDialectErrorBody(dialect) {
  const body = dialect.errorBody(PROVIDER_ACCOUNT_ERROR_STATUS, PROVIDER_ACCOUNT_ERROR_MESSAGE);
  if (isPlainObject(body) && isPlainObject(body.error)) body.error.code = PROVIDER_ACCOUNT_ERROR_CODE;
  return JSON.stringify(body);
}

/** What the client gets when the upstream "error" is too large to be one. */
export function genericErrorBody(statusCode) {
  return JSON.stringify({ error: { message: 'upstream error', code: statusCode } });
}

/**
 * A buffered upstream ERROR body made safe to write (the decisions route,
 * which has the whole answer in hand): the two passes above, with the same two
 * escapes sanitizedErrorStream (below) takes on the chat path — a body over
 * MAX_ERROR_BODY_BYTES is not an error body, and a sanitizer that throws (the
 * byte bound does not bound nesting) must still deliver a safe body. Returns
 * the bytes to write and whether they are the generic replacement. A provider
 * account error (above) is replaced too, and says so: the caller serves
 * PROVIDER_ACCOUNT_ERROR_STATUS with it.
 */
export function sanitizedErrorBodyBuffer(body, statusCode) {
  if (body.length > MAX_ERROR_BODY_BYTES) {
    if (isProviderAccountError(statusCode)) {
      return { body: Buffer.from(providerAccountErrorBody(), 'utf8'), replaced: true, accountError: true };
    }
    return { body: Buffer.from(genericErrorBody(statusCode), 'utf8'), replaced: true };
  }
  try {
    const text = body.toString('utf8');
    if (isProviderAccountError(statusCode, text)) {
      return { body: Buffer.from(providerAccountErrorBody(), 'utf8'), replaced: true, accountError: true };
    }
    return { body: Buffer.from(sanitizeUpstreamErrorBody(text), 'utf8'), replaced: false };
  } catch {
    return { body: Buffer.from(genericErrorBody(statusCode), 'utf8'), replaced: true };
  }
}

/**
 * Wrap an upstream error response so the pipeline downstream (extractor,
 * rewriter, settle) sees one sanitized body instead of the raw bytes. The body
 * is buffered to its end first — the fields to delete can straddle any chunk
 * boundary, and an error status is a finite JSON document, never a stream.
 * Same shape as tinfoil's decryptedStream: an upstream error destroys the
 * wrapper, a wrapper error releases the upstream socket.
 *
 * A provider account error (above) becomes the replacement body, and
 * `onAccountError` is called once, before that body is pushed, so the caller
 * can choose the status line it has been holding for it.
 */
export function sanitizedErrorStream(upRes, statusCode, { onAccountError } = {}) {
  const chunks = [];
  let size = 0;
  let overflow = false;
  const t = new Transform({
    transform(chunk, _enc, cb) {
      if (!overflow) {
        size += chunk.length;
        if (size > MAX_ERROR_BODY_BYTES) {
          overflow = true;
          chunks.length = 0;
        } else {
          chunks.push(chunk);
        }
      }
      cb();
    },
    flush(cb) {
      let out;
      let accountError = false;
      if (overflow) {
        accountError = isProviderAccountError(statusCode);
        out = genericErrorBody(statusCode);
      } else {
        try {
          const text = Buffer.concat(chunks).toString('utf8');
          accountError = isProviderAccountError(statusCode, text);
          out = accountError ? '' : sanitizeUpstreamErrorBody(text);
        } catch {
          // The byte bound does not bound nesting: a 10 KB body of 5,000
          // nested arrays parses and then overflows the recursive wording
          // pass (CodeRabbit). A sanitizer that fails must still deliver a
          // safe body, never a dead stream.
          out = genericErrorBody(statusCode);
        }
      }
      if (accountError) {
        out = providerAccountErrorBody();
        try {
          onAccountError?.();
        } catch {
          // The caller's hook must never cost the client its body.
        }
      }
      cb(null, Buffer.from(out, 'utf8'));
    },
  });
  upRes.on('error', (e) => t.destroy(e));
  t.once('error', () => {
    if (!upRes.destroyed) upRes.destroy();
  });
  return upRes.pipe(t);
}
