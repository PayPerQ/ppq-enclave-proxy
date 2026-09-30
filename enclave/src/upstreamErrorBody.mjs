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

/** The JSON pass: drop the fields that name the upstream or our account with it. */
export function stripUpstreamIdentity(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return text;
  }
  if (!isPlainObject(parsed)) return text;
  delete parsed.user_id;
  // OpenRouter nests `metadata` under `error`; a top-level one is handled too
  // so a shape change upstream cannot quietly reopen the leak.
  for (const holder of [parsed, parsed.error]) {
    if (isPlainObject(holder) && isPlainObject(holder.metadata)) {
      delete holder.metadata.provider_name;
    }
  }
  return JSON.stringify(parsed);
}

/** The wording pass, mirroring horse-power: links, the docs pointer, the name. */
export function sanitizeUpstreamWording(text) {
  let s = text.replace(/https?:\/\/(www\.)?openrouter\.ai[^\s"')\]]*[^\s"')\],.]*/gi, '');
  s = s.replace(/Please refer to our docs:/gi, '');
  s = s.replace(/openrouter/gi, 'AI Provider');
  s = s.replace(/\s{2,}/g, ' ');
  s = s.replace(/\s+([,.)])/, '$1');
  return s;
}

export function sanitizeUpstreamErrorBody(text) {
  return sanitizeUpstreamWording(stripUpstreamIdentity(text));
}

/** What the client gets when the upstream "error" is too large to be one. */
export function genericErrorBody(statusCode) {
  return JSON.stringify({ error: { message: 'upstream error', code: statusCode } });
}

/**
 * Wrap an upstream error response so the pipeline downstream (extractor,
 * rewriter, settle) sees one sanitized body instead of the raw bytes. The body
 * is buffered to its end first — the fields to delete can straddle any chunk
 * boundary, and an error status is a finite JSON document, never a stream.
 * Same shape as tinfoil's decryptedStream: an upstream error destroys the
 * wrapper, a wrapper error releases the upstream socket.
 */
export function sanitizedErrorStream(upRes, statusCode) {
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
      const out = overflow
        ? genericErrorBody(statusCode)
        : sanitizeUpstreamErrorBody(Buffer.concat(chunks).toString('utf8'));
      cb(null, Buffer.from(out, 'utf8'));
    },
  });
  upRes.on('error', (e) => t.destroy(e));
  t.once('error', () => {
    if (!upRes.destroyed) upRes.destroy();
  });
  return upRes.pipe(t);
}
