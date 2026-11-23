/**
 * What a FAILED direct attempt was about, read from the provider's own error
 * envelope, for the one provider where the status alone does not say.
 *
 * A failed direct response is normally drained unread (server.mjs `drain`):
 * the candidate loop moves on and the status is all the refusal needs. For
 * Abliteration AI it is not enough. Its platform safety filter answers a
 * match with 403 `policy_violation`, and 403 is also what a permission
 * problem on our own key would be. The first is the caller's content, answered
 * 400 with nothing to retry; the second is an outage on our side, answered
 * 503. Told apart only by the envelope's `code` / `type`, so the envelope is
 * read: bounded, timed, and reduced to one of a closed set of kinds.
 *
 * WHAT IS AND IS NOT KEPT. An upstream error envelope is provider-authored
 * text about the request, not query content (the same footing as
 * upstreamErrorBody.mjs). Only `error.code` and `error.type` are read, each
 * compared against literals; nothing from the body is logged, traced,
 * settled, returned to the caller or retained. The result is an enum.
 *
 * Mirror of horse-power abliterationAdapter.ts `abliterationContentBail`,
 * which makes the same decision from the same fields.
 */

/** An error envelope is a few hundred bytes; past this it is not one. */
export const FAILURE_BODY_MAX_BYTES = 16 * 1024;
/** The caller is waiting on a refusal: do not hold it for a slow error body. */
export const FAILURE_BODY_TIMEOUT_MS = 2000;

/** The closed set of kinds a failure can be classified as. */
export const FAILURE_KINDS = Object.freeze(['content_policy', 'too_many_images', 'unsupported_media']);

/** The one provider whose failed bodies are read. */
export const BODY_CLASSIFIED_PROVIDER = 'abliteration';

/**
 * Read a failed response body, bounded in size and time. Resolves with the
 * text, or undefined when the body is over the cap, errors, or does not end
 * in time; in every case the stream is left destroyed or fully consumed, so
 * the socket is released exactly as `drain` would release it. Never rejects.
 *
 * @param {import('node:http').IncomingMessage} upRes
 * @param {{maxBytes?: number, timeoutMs?: number}} [o]
 * @returns {Promise<string|undefined>}
 */
export function readFailureBody(upRes, { maxBytes = FAILURE_BODY_MAX_BYTES, timeoutMs = FAILURE_BODY_TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const giveUp = () => {
      // An `error` after destroy must not reach an unhandled listener.
      upRes.on('error', () => {});
      upRes.destroy();
      finish(undefined);
    };
    const timer = setTimeout(giveUp, timeoutMs);
    upRes.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) return giveUp();
      chunks.push(chunk);
    });
    upRes.on('end', () => finish(Buffer.concat(chunks).toString('utf8')));
    upRes.on('error', () => finish(undefined));
    upRes.on('close', () => finish(undefined));
  });
}

/**
 * The kind of an Abliteration AI failure, or undefined when the status class
 * should decide (a rejected key, a rate limit, a permission 403, an envelope
 * that does not parse).
 *
 * @param {number|undefined} status
 * @param {string|undefined} text the error envelope, as read
 * @returns {'content_policy'|'too_many_images'|'unsupported_media'|undefined}
 */
export function abliterationFailureKind(status, text) {
  if (!Number.isInteger(status) || status < 400 || status > 499) return undefined;
  if (typeof text !== 'string' || text.length === 0) return undefined;
  let err;
  try {
    err = JSON.parse(text)?.error;
  } catch {
    return undefined;
  }
  if (typeof err !== 'object' || err === null) return undefined;
  const code = typeof err.code === 'string' ? err.code : undefined;
  const type = typeof err.type === 'string' ? err.type : undefined;
  if (status === 403 && (code === 'policy_violation' || type === 'policy_error' || type === 'moderation_error')) {
    return 'content_policy';
  }
  if (type === 'media_error') {
    return code === 'media_count_exceeded' ? 'too_many_images' : 'unsupported_media';
  }
  return undefined;
}

/**
 * Whether a failed attempt's body is worth reading at all: this provider, a
 * 4xx that is not one the status already explains (401 a rejected key, 429 a
 * rate limit). Everything else is drained by the caller as before.
 */
export function shouldClassifyFailureBody(provider, status) {
  return (
    provider === BODY_CLASSIFIED_PROVIDER &&
    Number.isInteger(status) &&
    status >= 400 &&
    status <= 499 &&
    status !== 401 &&
    status !== 429
  );
}
