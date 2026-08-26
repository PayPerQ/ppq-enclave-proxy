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
  /** Enclave-local model validation rejected the slug before any spend. */
  MODEL_REJECTED: 'model_rejected',
  /** Payload transform threw (provider directive, cache_control shaping, ...). */
  TRANSFORM_FAILED: 'transform_failed',
  /** Every candidate upstream failed; nothing was served. */
  UPSTREAM_UNREACHABLE: 'upstream_unreachable',
  /** An upstream accepted, then broke mid-stream. User saw a truncated answer. */
  STREAM_FAILED: 'stream_failed',
  /** horse-power refused the request at /authorize. */
  AUTHORIZE_REJECTED: 'authorize_rejected',
});

const CODES = new Set(Object.values(ERROR_CODES));

/** Catalog identifiers only — the shape a slug has and a sentence does not. */
const LABEL_RE = /^[a-zA-Z0-9._:/@-]+$/;

function label(value, max = 96) {
  if (typeof value !== 'string' || !value) return undefined;
  const trimmed = value.slice(0, max);
  return LABEL_RE.test(trimmed) ? trimmed : undefined;
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
  const request_id = label(fields.request_id);
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
