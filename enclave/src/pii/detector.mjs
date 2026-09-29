/**
 * Detector adapter: one contract, placement chosen by configuration.
 *
 *   const d = createDetector({ kind, url, apiKey, fetch, timeoutMs })
 *   const { spans, calls } = await d.detect(texts, { signal })
 *
 * `spans[i]` are `{ start, end, cls }` on `texts[i]`, in UTF-16 code units (the
 * unit pseudonymize() uses). Both placements are Python services that report
 * offsets in code points, so they are converted here. Empty / whitespace-only
 * texts are not sent; if every text is empty no request is made (`calls: 0`).
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
      try {
        return await res.json();
      } catch {
        throw new DetectorError(why ?? 'bad_response');
      }
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
      if (parts.length === 0) return { spans, calls: 0 };

      let found;
      if (kind === 'tinfoil-hosted') {
        let offset = 0;
        for (const p of parts) {
          p.offset = offset;
          offset += p.text.length + separator.length;
        }
        const joined = parts.map((p) => p.text).join(separator);
        found = hostedSpans(joined, parts, await post({ text: joined }, signal));
      } else {
        found = selfSpans(parts, await post({ texts: parts.map((p) => p.text) }, signal));
      }

      parts.forEach((p, k) => {
        for (const s of found[k]) {
          const [start, end] = trimEdges(p.text, s.start, s.end);
          if (start < end) spans[p.index].push({ start, end, cls: s.cls });
        }
      });
      return { spans, calls: 1 };
    },
  };
}
