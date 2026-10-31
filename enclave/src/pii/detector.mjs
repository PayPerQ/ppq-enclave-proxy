/**
 * Detector adapter: one contract, placement chosen by configuration.
 *
 *   const d = createDetector({ kind, url, apiKey, fetch, timeoutMs })
 *   const { spans, calls, inputTokens, inputTokensEstimated } = await d.detect(texts, { signal })
 *
 * `spans[i]` are `{ start, end, cls }` on `texts[i]`, in UTF-16 code units (the
 * unit pseudonymize() uses). Both placements are Python services that report
 * offsets in code points, so they are converted here. Empty / whitespace-only
 * texts are not sent; if every text is empty no request is made (`calls: 0`).
 *
 * `inputTokens` is what the detector bills the call at. Tinfoil prices the
 * filter per input token plus a per-request fee (2026-10-30) and returns the
 * metered count on every 200 as `x-tinfoil-billable-input-tokens`; it is read
 * off the response and reported to hp on the settle, never re-tokenized here.
 * The header is the operator's billing receipt, carried over the attested TLS
 * session but outside the EHBP-sealed body (as Tinfoil's chat usage header
 * is): it is trusted as far as the party we pay is, not as measured detector
 * output. A 200 without a usable receipt (absent, zero for text that was sent,
 * or not a bounded integer — the gateway refuses to send such a 200, so this
 * is contract drift) falls back to the gateway's own size rule over the text
 * sent, one token per four UTF-8 bytes, and says so (`inputTokensEstimated`).
 * A 200 whose body cannot be used (bad_response / unknown_label) is still a
 * billed call: the rejection carries `billed: { calls, inputTokens, … }` so
 * the caller can report the unbilled spend.
 *
 * Placements:
 *   'tinfoil-hosted'  POST {text} -> {detected_spans:[{label,start,end}]}.
 *                     One text per call, so texts are joined with `separator`
 *                     and offsets mapped back (a span crossing a separator is
 *                     clipped to each side). Hosted labels map onto our classes;
 *                     an unknown label fails closed.
 *   'tinfoil-self'    POST {texts} -> {spans:[[{start,end,cls,score}]]}.
 *
 * Fail-closed: any timeout, abort, non-2xx, network error, malformed body or
 * unknown label rejects with DetectorError. Error messages never carry text.
 *
 * Pure: no node:* imports; `fetch` is injected (defaults to globalThis.fetch).
 */
import { PII_CLASSES } from './core.mjs';

export const DEFAULT_TIMEOUT_MS = 60_000;
/**
 * The Tinfoil-hosted filter the 'tinfoil-hosted' placement calls. A measured
 * constant: the detector receives cleartext PII, so where it goes is part of
 * the published build, not something the parent's init blob can choose.
 */
export const HOSTED_DETECTOR_HOST = 'pii-filter.tinfoil.sh';
export const HOSTED_DETECTOR_PATH = '/redact';
/** The detector's billing receipt: the input tokens this call is metered at. */
export const BILLABLE_INPUT_TOKENS_HEADER = 'x-tinfoil-billable-input-tokens';
/** The detector refuses longer inputs with 413 (`OPF_MAX_INPUT_TOKENS`, 80k since 2026-10-30). */
export const DETECTOR_MAX_INPUT_TOKENS = 80_000;
/** A receipt (or estimate) above this is not a count: headroom over the limit for a raised one, no more. */
export const MAX_BILLABLE_INPUT_TOKENS = 10 * DETECTOR_MAX_INPUT_TOKENS;
export const DETECTOR_KINDS = Object.freeze(['tinfoil-hosted', 'tinfoil-self']);

/** Hosted filter label -> our class. `null` = recognised but not a v1 class (dropped). */
export const HOSTED_LABELS = Object.freeze({
  private_person: 'PERSON',
  private_email: 'EMAIL',
  private_phone: 'PHONE',
  private_address: 'ADDRESS',
  account_number: 'ID',
  secret: 'ID',
  // The hosted model labels bare IP addresses as private_url.
  private_url: 'IP',
  // Dates (incl. dates of birth) are not a v1 class.
  private_date: null,
});

// Span edges the models tend to include; trimmed so placeholders do not
// swallow the surrounding punctuation.
const EDGE = new Set([' ', '\t', '\n', '\r', '.', ',', ';', ':', '!', '?', '"', "'", '(', ')', '[', ']', '<', '>']);

export class DetectorError extends Error {
  /** @param reason timeout | aborted | http_status | network | bad_response | unknown_label | bad_config */
  constructor(reason, { status } = {}) {
    super(`pii detector failed: ${reason}${status ? ` (${status})` : ''}`);
    this.name = 'DetectorError';
    this.code = 'pii_detector_failed';
    this.reason = reason;
    if (status !== undefined) this.status = status;
  }
}

/** cp -> UTF-16 offset table for `text`: table[k] = UTF-16 index of code point k. */
function codePointTable(text) {
  const table = [];
  let u = 0;
  for (const ch of text) {
    table.push(u);
    u += ch.length;
  }
  table.push(u);
  return table;
}

function trimEdges(text, start, end) {
  while (start < end && EDGE.has(text[start])) start++;
  while (end > start && EDGE.has(text[end - 1])) end--;
  return [start, end];
}

const isIndex = (n) => Number.isInteger(n) && n >= 0;

const utf8Bytes = (text) => new TextEncoder().encode(text).length;

/**
 * The gateway's own approximation when a receipt is missing (DEPLOYMENT.md:
 * it sizes a request at one token per four bytes of body; the body is the
 * text plus a few bytes of JSON framing, so the text's bytes are the same
 * rule from below). Bounded like a receipt.
 */
export function estimateInputTokens(text) {
  return Math.min(Math.max(1, Math.ceil(utf8Bytes(text) / 4)), MAX_BILLABLE_INPUT_TOKENS);
}

/**
 * The metered count from the response, or null when the header is absent or
 * not a plain bounded positive integer (`headers` is a fetch Headers or
 * absent). Zero is not a count for text that was sent.
 */
export function billableInputTokens(headers) {
  const raw = typeof headers?.get === 'function' ? headers.get(BILLABLE_INPUT_TOKENS_HEADER) : null;
  if (typeof raw !== 'string' || !/^\d{1,8}$/.test(raw.trim())) return null;
  const n = Number(raw.trim());
  return n >= 1 && n <= MAX_BILLABLE_INPUT_TOKENS ? n : null;
}

/** Validate a code-point span against `table`, convert to UTF-16. */
function toUtf16(table, start, end) {
  if (!isIndex(start) || !isIndex(end) || start > end || end >= table.length) throw new DetectorError('bad_response');
  return [table[start], table[end]];
}

function hostedSpans(joined, parts, body) {
  if (!body || !Array.isArray(body.detected_spans)) throw new DetectorError('bad_response');
  const table = codePointTable(joined);
  const out = parts.map(() => []);
  for (const s of body.detected_spans) {
    if (!s || typeof s !== 'object') throw new DetectorError('bad_response');
    if (!Object.hasOwn(HOSTED_LABELS, s.label)) throw new DetectorError('unknown_label');
    const cls = HOSTED_LABELS[s.label];
    const [start, end] = toUtf16(table, s.start, s.end);
    if (cls === null) continue;
    parts.forEach((p, k) => {
      const a = Math.max(start, p.offset) - p.offset;
      const b = Math.min(end, p.offset + p.text.length) - p.offset;
      if (a < b) out[k].push({ start: a, end: b, cls });
    });
  }
  return out;
}

function selfSpans(parts, body) {
  if (!body || !Array.isArray(body.spans) || body.spans.length !== parts.length) throw new DetectorError('bad_response');
  return parts.map((p, k) => {
    const list = body.spans[k];
    if (!Array.isArray(list)) throw new DetectorError('bad_response');
    const table = codePointTable(p.text);
    return list.map((s) => {
      if (!s || typeof s !== 'object') throw new DetectorError('bad_response');
      if (!PII_CLASSES.includes(s.cls)) throw new DetectorError('unknown_label');
      const [start, end] = toUtf16(table, s.start, s.end);
      return { start, end, cls: s.cls };
    });
  });
}

export function createDetector({
  kind,
  url,
  apiKey,
  fetch: fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  separator = '\n\n',
} = {}) {
  if (!DETECTOR_KINDS.includes(kind)) throw new DetectorError('bad_config');
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) throw new DetectorError('bad_config');
  if (typeof fetchImpl !== 'function') throw new DetectorError('bad_config');
  if (!(Number.isFinite(timeoutMs) && timeoutMs > 0)) throw new DetectorError('bad_config');

  async function post(payload, signal) {
    if (signal?.aborted) throw new DetectorError('aborted');
    const ctrl = new AbortController();
    let why = null;
    const timer = setTimeout(() => {
      why = 'timeout';
      ctrl.abort();
    }, timeoutMs);
    const onAbort = () => {
      why ??= 'aborted';
      ctrl.abort();
    };
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const headers = { 'content-type': 'application/json' };
      if (apiKey) headers.authorization = `Bearer ${apiKey}`;
      let res;
      try {
        res = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(payload), signal: ctrl.signal });
      } catch {
        throw new DetectorError(why ?? 'network');
      }
      if (why) throw new DetectorError(why);
      if (!res || !res.ok) throw new DetectorError('http_status', { status: res?.status });
      let json;
      try {
        json = await res.json();
      } catch {
        const err = new DetectorError(why ?? 'bad_response');
        // A 200 was answered: the call is billed whatever its body says, and
        // whether the body was unusable, slow (timeout) or abandoned (abort).
        err.answered = { headers: res.headers };
        throw err;
      }
      return { json, headers: res.headers };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener?.('abort', onAbort);
    }
  }

  return {
    kind,
    timeoutMs,
    async detect(texts, { signal } = {}) {
      if (!Array.isArray(texts) || !texts.every((t) => typeof t === 'string')) throw new TypeError('texts must be an array of strings');
      const spans = texts.map(() => []);
      const parts = [];
      texts.forEach((text, index) => {
        if (text.trim() !== '') parts.push({ index, text });
      });
      if (parts.length === 0) return { spans, calls: 0, inputTokens: 0, inputTokensEstimated: false };

      let found;
      let answer = null;
      const sent = parts.map((p) => p.text).join(separator);
      const usage = (headers) => {
        const metered = billableInputTokens(headers);
        return { inputTokens: metered ?? estimateInputTokens(sent), inputTokensEstimated: metered == null };
      };
      try {
        if (kind === 'tinfoil-hosted') {
          let offset = 0;
          for (const p of parts) {
            p.offset = offset;
            offset += p.text.length + separator.length;
          }
          answer = await post({ text: sent }, signal);
          found = hostedSpans(sent, parts, answer.json);
        } else {
          answer = await post({ texts: parts.map((p) => p.text) }, signal);
          found = selfSpans(parts, answer.json);
        }
      } catch (e) {
        // Past a 200 the detector has billed the call (DEPLOYMENT.md: one usage
        // event per 200), usable body or not: let the caller account for it.
        const answered = answer ?? e?.answered;
        if (e instanceof DetectorError && answered) e.billed = { calls: 1, ...usage(answered.headers) };
        throw e;
      }
      const { inputTokens, inputTokensEstimated } = usage(answer.headers);

      parts.forEach((p, k) => {
        for (const s of found[k]) {
          const [start, end] = trimEdges(p.text, s.start, s.end);
          if (start < end) spans[p.index].push({ start, end, cls: s.cls });
        }
      });
      return { spans, calls: 1, inputTokens, inputTokensEstimated };
    },
  };
}
