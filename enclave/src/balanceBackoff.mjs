/**
 * The enclave's memory of horse-power's balance backoff (horse-power #1022).
 *
 * An abandoned agent keeps retrying long after its balance hit $0 — one
 * account alone sent ~63k requests a day for weeks. Every one of those went
 * enclave → hp `/enclave/authorize` → 402, and then enclave → hp
 * `/enclave/error` to report the refusal. hp now answers such an account with
 * **429 + `Retry-After`** and the body code `balance_backoff` once it has
 * refused it more than a threshold of times in the hour (its own
 * `balanceRejectBackoff`). This module makes the enclave honour that answer
 * on its own:
 *
 * - the refusal is remembered against the PRESENTED credential for exactly
 *   the `Retry-After` hp named, and a repeat inside that window is answered
 *   here, with the same 429 and body, without a round trip to hp;
 * - a backoff refusal is not an enclave failure, so it is not reported to
 *   `/enclave/error` (server.mjs); it still counts as a request outcome.
 *
 * The window is hp's, never ours: hp will not re-read the balance before it
 * either, so a top-up is noticed at the same moment it would have been. The
 * cap on what we honour (MAX_RETRY_AFTER_SECONDS) is the same as hp's, so a
 * misconfigured or forged value cannot hold a credential longer than that.
 *
 * Content-free by construction: the key is a SHA-256 of the credential
 * string (never the credential, never the request body); the stored body is
 * hp's own JSON refusal, which carries a credit-id PREFIX at most. Bounded
 * map, per worker, non-durable — the same shape as hp's limiter.
 */
import { createHash } from 'node:crypto';

/** The longest window we honour; mirrors hp's `MAX_RETRY_AFTER_SECONDS`. */
export const MAX_RETRY_AFTER_SECONDS = 60;
/** The body code hp sets on a balance backoff refusal (`rejectInBalanceBackoff`). */
export const BALANCE_BACKOFF_CODE = 'balance_backoff';
/** Credentials remembered per worker at most; past it the oldest is evicted. */
export const MAX_TRACKED_CREDENTIALS = 10_000;

/**
 * The credential hp will resolve the account from, hashed. Same precedence
 * as hp's `utils/presentedCredential.ts`: a Bearer token wins; otherwise
 * `x-credit-id` beats `x-api-key` (hp drops x-api-key when a credit id is
 * present). Returns null when the request carries none — such a request is
 * refused by hp as unauthenticated and is never remembered.
 *
 * @param {import('node:http').IncomingHttpHeaders | undefined} headers
 * @returns {string | null} a hex SHA-256, or null
 */
export function presentedCredentialKey(headers) {
  if (!headers || typeof headers !== 'object') return null;
  const auth = headers.authorization;
  const bearer = typeof auth === 'string' ? /^bearer[ \t]+(\S.*)$/i.exec(auth)?.[1] : undefined;
  const creditId = typeof headers['x-credit-id'] === 'string' && headers['x-credit-id'] !== '' ? headers['x-credit-id'] : undefined;
  const xApiKey = typeof headers['x-api-key'] === 'string' && headers['x-api-key'] !== '' ? headers['x-api-key'] : undefined;
  const credential = bearer || creditId || xApiKey;
  if (!credential) return null;
  return createHash('sha256').update(credential).digest('hex');
}

/**
 * The seconds a 429 asked the client to wait, as an integer in
 * 1..MAX_RETRY_AFTER_SECONDS, or null when neither source names a usable
 * value. The header wins (RFC 9110 delta-seconds only; an HTTP-date is not
 * something hp sends and is not honoured); hp's body field
 * `retry_after_seconds` is the fallback for a hop that stripped the header.
 *
 * @param {unknown} headerValue   the `retry-after` response header
 * @param {unknown} bodyValue     `body.retry_after_seconds`
 * @returns {number | null}
 */
export function retryAfterSeconds(headerValue, bodyValue) {
  for (const raw of [headerValue, bodyValue]) {
    const n = typeof raw === 'string' ? (/^\d{1,6}$/.test(raw.trim()) ? Number(raw.trim()) : NaN) : raw;
    if (typeof n === 'number' && Number.isFinite(n) && n >= 1) {
      return Math.min(MAX_RETRY_AFTER_SECONDS, Math.floor(n));
    }
  }
  return null;
}

/**
 * Whether an authorize answer is hp's balance backoff — the one refusal the
 * enclave remembers and does not report. A credential-rate-limit 429
 * (`credential_rate_limit`) is not: that limiter is keyed on the presented
 * credential and cheap on hp, and the enclave has no business extending it.
 *
 * @param {number | undefined} status
 * @param {unknown} body
 */
export function isBalanceBackoffRefusal(status, body) {
  return status === 429 && !!body && typeof body === 'object' && body.code === BALANCE_BACKOFF_CODE;
}

/**
 * @param {{ now?: () => number }} [opts]  injectable clock for tests
 */
export function createBalanceBackoff({ now = () => Date.now() } = {}) {
  /** @type {Map<string, { until: number, body: unknown }>} */
  const held = new Map();

  function sweep(t) {
    for (const [k, v] of held) {
      if (t >= v.until) held.delete(k);
    }
  }

  return {
    /**
     * Remember hp's backoff refusal for this credential. `seconds` is the
     * value already bounded by retryAfterSeconds(); anything else is ignored
     * rather than clamped here, so there is exactly one place that decides
     * what is honoured.
     */
    remember(key, { seconds, body }) {
      if (typeof key !== 'string' || !key) return false;
      if (!Number.isInteger(seconds) || seconds < 1 || seconds > MAX_RETRY_AFTER_SECONDS) return false;
      const t = now();
      if (held.size >= MAX_TRACKED_CREDENTIALS && !held.has(key)) {
        sweep(t);
        while (held.size >= MAX_TRACKED_CREDENTIALS) {
          const oldest = held.keys().next().value;
          if (oldest === undefined) break;
          held.delete(oldest);
        }
      }
      held.set(key, { until: t + seconds * 1000, body });
      return true;
    },

    /**
     * The answer to give locally, or null when hp should be asked. `seconds`
     * is what is left of hp's window, rounded up and never below 1, so the
     * client is never told a shorter wait than the one that is really left.
     */
    lookup(key) {
      if (typeof key !== 'string' || !key) return null;
      const entry = held.get(key);
      if (!entry) return null;
      const t = now();
      if (t >= entry.until) {
        held.delete(key);
        return null;
      }
      return { status: 429, body: entry.body, seconds: Math.max(1, Math.ceil((entry.until - t) / 1000)) };
    },

    /** Credentials currently held. Gauge / test seam. */
    size() {
      return held.size;
    },

    /** Test seam. */
    clear() {
      held.clear();
    },
  };
}
