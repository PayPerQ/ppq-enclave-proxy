/**
 * The request/response glue around pii-core for the API routes: the
 * `pii_redaction` flag rule, the detect + pseudonymize step, and response
 * restorers that work on raw upstream bytes (SSE or a JSON body) through a
 * dialect adapter (dialects/*.mjs).
 *
 * The mapping never leaves the request that created it and nothing here logs:
 * restorers report counts only (`misses`).
 */
import { StringDecoder } from 'node:string_decoder';
import { pseudonymize, placeholderPattern } from './core.mjs';

export const PII_FIELD = 'pii_redaction';

/** Client-facing error codes (the `error.code` of the JSON body). */
export const PII_ERRORS = Object.freeze({
  INVALID: 'pii_redaction_invalid',
  UNSUPPORTED_MODEL: 'pii_redaction_unsupported_model',
  UNAVAILABLE: 'pii_redaction_unavailable',
  UNSUPPORTED_STATE: 'pii_redaction_unsupported_state',
});

/**
 * Read and REMOVE `pii_redaction` from a parsed body, by value:
 * absent ⇒ 'absent' (body untouched); `false` ⇒ 'off'; `true` ⇒ 'on';
 * anything else ⇒ 'invalid'. The field is deleted whenever it is present, so
 * it can never be forwarded.
 */
export function takePiiFlag(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !Object.hasOwn(body, PII_FIELD)) return 'absent';
  const v = body[PII_FIELD];
  delete body[PII_FIELD];
  return v === true ? 'on' : v === false ? 'off' : 'invalid';
}

/** The JSON error body for one of PII_ERRORS. */
export function piiErrorBody(code) {
  const message =
    code === PII_ERRORS.INVALID
      ? 'pii_redaction must be a boolean'
      : code === PII_ERRORS.UNSUPPORTED_MODEL
        ? 'pii_redaction is not supported for private/* models'
        : code === PII_ERRORS.UNSUPPORTED_STATE
          ? 'pii_redaction is not supported with previous_response_id or conversation; send the full input instead'
          : 'PII redaction is unavailable; the request was not sent';
  return { error: { message, code } };
}

/**
 * Detect and pseudonymize every redactable text of `body` in one detector
 * call. Rejects with the detector's DetectorError on any failure (fail-closed:
 * the caller sends nothing upstream). Resolves to the redacted copy, the
 * mapping, and counts only.
 */
export async function redactBody(dialect, body, detector) {
  const refs = dialect.extractTexts(body);
  const texts = refs.map((r) => r.text);
  const { spans, calls } = await detector.detect(texts);
  const { texts: out, mapping } = pseudonymize(texts, spans);
  return {
    body: dialect.applyTexts(body, refs, out),
    mapping,
    calls,
    entities: mapping.byPlaceholder.size,
    texts: texts.length,
  };
}

/** Placeholder-shaped tokens left in `text` after restoration. */
function countMisses(text, mapping) {
  if (!text) return 0;
  return (text.match(placeholderPattern(mapping.grammar)) ?? []).length;
}

/**
 * Restorer for a `text/event-stream` body. `push(buf)` returns the restored
 * bytes ready to emit (possibly empty while an event is incomplete);
 * `finish()` returns everything still held. Events are split on blank lines
 * (CRLF normalised); every `data:` payload that parses as JSON goes through
 * the dialect's event restorer; comments, `[DONE]` and anything unparseable
 * pass through unchanged. A synthetic event is named after its own `type`
 * when the stream uses `event:` lines (Responses, Messages).
 */
export function createSseRestorer(dialect, mapping) {
  const events = dialect.createEventRestorer(mapping);
  const decoder = new StringDecoder('utf8');
  let buf = '';
  let named = false;
  let misses = 0;

  const render = (list, fallbackName) =>
    list
      .map((ev) => {
        const lines = [];
        if (named) lines.push(`event: ${typeof ev?.type === 'string' ? ev.type : fallbackName}`);
        lines.push(`data: ${JSON.stringify(ev)}`);
        const s = `${lines.join('\n')}\n\n`;
        misses += countMisses(s, mapping);
        return s;
      })
      .join('');

  const block = (b) => {
    const lines = b.split('\n');
    const data = lines.filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, ''));
    if (data.length === 0) return `${b}\n\n`;
    const payload = data.join('\n');
    if (payload.trim() === '[DONE]') return render(events.flush(), 'message') + `${b}\n\n`;
    let ev;
    try {
      ev = JSON.parse(payload);
    } catch {
      return `${b}\n\n`;
    }
    const nameLine = lines.find((l) => l.startsWith('event:'));
    if (nameLine) named = true;
    const keep = lines.filter((l) => !l.startsWith('data:') && !l.startsWith('event:'));
    const prefix = keep.length ? `${keep.join('\n')}\n` : '';
    return prefix + render(events.push(ev), nameLine ? nameLine.slice(6).trim() : 'message');
  };

  const drain = (final) => {
    let out = '';
    // A lone trailing CR may be the first half of a CRLF split across chunks.
    let text = buf;
    let held = '';
    if (!final && text.endsWith('\r')) {
      held = '\r';
      text = text.slice(0, -1);
    }
    text = text.replace(/\r\n?/g, '\n');
    let i;
    while ((i = text.indexOf('\n\n')) !== -1) {
      out += block(text.slice(0, i));
      text = text.slice(i + 2);
    }
    buf = text + held;
    return out;
  };

  return {
    push(chunk) {
      buf += decoder.write(chunk);
      return Buffer.from(drain(false), 'utf8');
    },
    finish() {
      buf += decoder.end();
      let out = drain(true);
      if (buf.trim() !== '') out += block(buf.replace(/\n+$/, ''));
      buf = '';
      out += render(events.flush(), 'message');
      return Buffer.from(out, 'utf8');
    },
    get misses() {
      return misses;
    },
  };
}

/**
 * Restorer for a non-stream JSON body: held whole, restored once at the end
 * with the dialect's `restoreJson` (tool-call arguments included). A body that
 * is not JSON (an upstream error page) passes through unchanged.
 */
export function createJsonRestorer(dialect, mapping) {
  const chunks = [];
  let misses = 0;
  return {
    push(chunk) {
      chunks.push(chunk);
      return Buffer.alloc(0);
    },
    finish() {
      const raw = Buffer.concat(chunks);
      let parsed;
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        return raw;
      }
      const out = JSON.stringify(dialect.restoreJson(parsed, mapping));
      misses = countMisses(out, mapping);
      return Buffer.from(out, 'utf8');
    },
    get misses() {
      return misses;
    },
  };
}

/** The restorer for a response of `contentType`. */
export function createResponseRestorer(dialect, mapping, contentType) {
  return /text\/event-stream/i.test(String(contentType ?? ''))
    ? createSseRestorer(dialect, mapping)
    : createJsonRestorer(dialect, mapping);
}
