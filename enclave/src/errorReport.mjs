/**
 * Content-free failure reports to horse-power.
 *
 * WHY THIS EXISTS
 * ---------------
 * `log()` in this file's sibling is content-free and has ~19 call sites, but it
 * writes to a console nobody can read: `nitro-cli console` requires
 * `--debug-mode`, which zeroes PCR0 and would make every pinned client reject
 * the enclave. And `/enclave/settle` only fires after a successful stream, so
 * every early return here left no trace on PPQ's side at all. The only signal
 * was the browser's own Sentry report — which meant API callers were invisible.
 *
 * WHY AN ENUM AND NOT A MESSAGE
 * -----------------------------
 * This is the one component that sees prompts in the clear, and the whole point
 * of it is that PayPerQ never does. Upstream providers routinely quote request
 * content back inside error bodies — a 400 can echo the offending message, a
 * moderation refusal can quote the prompt. Forwarding provider strings would be
 * a content leak wearing a debugging hat, and it would leak exactly the requests
 * that went wrong, which are the ones most likely to be sensitive.
 *
 * So callers pick from a fixed vocabulary. `e.message` must never reach this
 * module; it belongs in `log()`, which stays inside the enclave.
 *
 * DRIFT HAZARD: mirrored in horse-power services/enclaveErrorCodes.ts, which
 * rejects codes it does not know. Additions must land there FIRST — this build
 * is pinned and rebuilt independently, so a code hp has not seen yet would be
 * reported and dropped.
 */

export const ERROR_CODES = Object.freeze({
  /** Sealed request could not be opened or parsed (EHBP header with no body). */
  REQUEST_UNREADABLE: 'request_unreadable',
  /**
   * Enclave-local model validation rejected the request before any spend.
   *
   * Split by REASON rather than reporting the offending slug: at this point the
   * model string came straight out of the decrypted body and nothing has proved
   * it is a catalog value, so echoing it would put caller-controlled text into
   * our logs. The reason is also the more useful signal — "someone pointed a
   * private/* model at the wrong endpoint" beats seeing the slug.
   */
  MODEL_REJECTED: 'model_rejected',
  MODEL_REJECTED_NOT_STRING: 'model_rejected_not_string',
  MODEL_REJECTED_SMART_ROUTING: 'model_rejected_smart_routing',
  MODEL_REJECTED_PRIVATE_PATH: 'model_rejected_private_path',
  /** Payload transform threw (provider directive, cache_control shaping, ...). */
  TRANSFORM_FAILED: 'transform_failed',
  /** Every candidate upstream failed; nothing was served. */
  UPSTREAM_UNREACHABLE: 'upstream_unreachable',
  /** An upstream accepted, then broke mid-stream. User saw a truncated answer. */
  STREAM_FAILED: 'stream_failed',
  /** horse-power refused the request at /authorize. */
  AUTHORIZE_REJECTED: 'authorize_rejected',
  /** An upstream answered, but with a 4xx/5xx that we passed through. */
  UPSTREAM_ERROR_STATUS: 'upstream_error_status',
  /** Anything the handler did not anticipate. Code only — never the message. */
  INTERNAL_ERROR: 'internal_error',
});

/**
 * Classify why resolveModel refused, without touching the offending value.
 * Mirrors the throw sites in routing.mjs; an unrecognised message degrades to
 * the generic code rather than being forwarded.
 */
export function classifyModelRejection(message) {
  const m = typeof message === 'string' ? message : '';
  if (m.includes('must be a string')) return ERROR_CODES.MODEL_REJECTED_NOT_STRING;
  if (m.includes('Smart-routing')) return ERROR_CODES.MODEL_REJECTED_SMART_ROUTING;
  if (m.includes('Tinfoil path')) return ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH;
  return ERROR_CODES.MODEL_REJECTED;
}

const CODES = new Set(Object.values(ERROR_CODES));

/**
 * Catalog identifiers only — the shape a slug has and a sentence does not.
 *
 * Bounded IN the pattern, and validated against the FULL string. Truncating
 * first and validating the stub would accept a 500-character value whose first
 * 96 characters happen to be slug-shaped, which is a strictly more permissive
 * boundary than "this looks like a model id". No real catalog slug is anywhere
 * near 96 characters, so rejecting overlength costs nothing legitimate.
 */
const LABEL_RE = /^[a-zA-Z0-9._:/@-]{1,96}$/;

function label(value) {
  if (typeof value !== 'string') return undefined;
  return LABEL_RE.test(value) ? value : undefined;
}

/**
 * Request ids, but ONLY ones this enclave generated.
 *
 * `requestId` in server.mjs falls back to the caller's `x-request-id` header,
 * so it is caller-controlled and must not be echoed into our logs and Sentry
 * tags. Matching the generated shape keeps correlation working for our own ids
 * and silently drops anyone else's.
 */
const ENCLAVE_REQUEST_ID_RE = /^enc-\d{10,}-[a-z0-9]{1,12}$/;

function enclaveRequestId(value) {
  if (typeof value !== 'string') return undefined;
  return ENCLAVE_REQUEST_ID_RE.test(value) ? value : undefined;
}

/**
 * Build the wire body for a failure report, or null if the code is unknown.
 *
 * Pure and exported so the containment property is testable without a socket:
 * whatever a caller passes, only allowlisted fields in an allowlisted shape can
 * come out the other side.
 */
export function buildErrorReport(code, fields = {}) {
  if (!CODES.has(code)) return null;
  // Not a bare Number(): Number(null) is 0, which is finite, so a missing status
  // would be reported as `upstream_status: 0` — a status code that does not
  // exist, arriving as though it were observed.
  const rawStatus = fields.upstream_status;
  const status =
    typeof rawStatus === 'number'
      ? rawStatus
      : typeof rawStatus === 'string' && rawStatus.trim() !== ''
        ? Number(rawStatus)
        : NaN;
  const body = { code };
  const request_id = enclaveRequestId(fields.request_id);
  const credit_id = label(fields.credit_id);
  const model = label(fields.model);
  const provider = label(fields.provider);
  const query_source = label(fields.query_source);
  if (request_id) body.request_id = request_id;
  if (credit_id) body.credit_id = credit_id;
  if (model) body.model = model;
  if (provider) body.provider = provider;
  if (query_source) body.query_source = query_source;
  if (Number.isFinite(status) && status > 0) body.upstream_status = status;
  return body;
}
