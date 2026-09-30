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
      let out;
      if (overflow) {
        out = genericErrorBody(statusCode);
      } else {
        try {
          out = sanitizeUpstreamErrorBody(Buffer.concat(chunks).toString('utf8'));
        } catch {
          // The byte bound does not bound nesting: a 10 KB body of 5,000
          // nested arrays parses and then overflows the recursive wording
          // pass (CodeRabbit). A sanitizer that fails must still deliver a
          // safe body, never a dead stream.
          out = genericErrorBody(statusCode);
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
