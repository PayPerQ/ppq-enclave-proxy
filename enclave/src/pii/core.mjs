/**
 * Reversible pseudonymization: replace detected PII spans with stable
 * placeholders and keep a request-scoped mapping to restore them later.
 *
 * Pure and runtime-agnostic on purpose: no I/O and no node:* imports, so the
 * same file runs in the enclave and, copied byte-for-byte, in a browser.
 *
 * Offsets: Span.start / Span.end are indices into the ORIGINAL string in
 * JavaScript's own unit (UTF-16 code units), end exclusive. Detector adapters
 * convert from whatever unit their detector reports (see detector.mjs).
 *
 * The mapping lives only in the memory of the request that created it; it is
 * never logged or persisted. Errors thrown here never include input text.
 */

export const PII_CLASSES = Object.freeze([
  'PERSON', 'EMAIL', 'PHONE', 'ADDRESS', 'ID', 'IBAN', 'CARD', 'IP', 'ORG', 'LOCATION',
]);
const CLASS_SET = new Set(PII_CLASSES);

/** Candidate placeholder grammars: `<open>CLASS_<n><close>`. */
export const GRAMMARS = Object.freeze({
  square: Object.freeze({ name: 'square', open: '[', close: ']' }),
  whiteSquare: Object.freeze({ name: 'whiteSquare', open: '⟦', close: '⟧' }),
  angle: Object.freeze({ name: 'angle', open: '<', close: '>' }),
});

export const DEFAULT_GRAMMAR = 'square';

function fail(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

export function grammarOf(grammar = DEFAULT_GRAMMAR) {
  const g = typeof grammar === 'string' ? GRAMMARS[grammar] : grammar;
  if (!g || typeof g.open !== 'string' || typeof g.close !== 'string' || !g.open || !g.close) {
    throw fail('pii_invalid_input', 'unknown placeholder grammar');
  }
  return g;
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Global regex matching any placeholder of `grammar` (issued or not). */
export function placeholderPattern(grammar) {
  const g = grammarOf(grammar);
  return new RegExp(`${escapeRe(g.open)}[A-Z]+_[0-9]+${escapeRe(g.close)}`, 'g');
}

/** Entity key: one placeholder per (class, normalized surface) within a request. */
function surfaceKey(cls, surface) {
  const norm = surface.normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
  return norm ? `${cls}\u0000${norm}` : '';
}

const isHigh = (c) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c) => c >= 0xdc00 && c <= 0xdfff;
const splitsPair = (text, i) => i > 0 && i < text.length && isHigh(text.charCodeAt(i - 1)) && isLow(text.charCodeAt(i));

function validSpan(text, s) {
  return s && Number.isInteger(s.start) && Number.isInteger(s.end)
    && s.start >= 0 && s.start <= s.end && s.end <= text.length
    && CLASS_SET.has(s.cls)
    && !splitsPair(text, s.start) && !splitsPair(text, s.end);
}

/**
 * Validate and merge the spans of one text. Overlapping spans become one span
 * covering their union (no part of any detected span is left in cleartext);
 * the longest member decides the class (tie: the earliest). Touching spans
 * stay separate. Zero-length spans are dropped. Throws on any invalid span.
 */
export function mergeSpans(text, spans) {
  for (const s of spans) {
    if (!validSpan(text, s)) throw fail('pii_invalid_span', 'invalid PII span');
  }
  const sorted = spans
    .filter((s) => s.end > s.start)
    .map((s) => ({ start: s.start, end: s.end, cls: s.cls }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let cur = null;
  let best = 0;
  for (const s of sorted) {
    if (cur && s.start < cur.end) {
      if (s.end - s.start > best) {
        best = s.end - s.start;
        cur.cls = s.cls;
      }
      cur.end = Math.max(cur.end, s.end);
    } else {
      cur = { ...s };
      best = s.end - s.start;
      out.push(cur);
    }
  }
  return out;
}

/**
 * @param {string[]} texts   every text of one request (all messages, memory, …)
 * @param {Array<Array<{start:number,end:number,cls:string}>>} spans  spans[i] belongs to texts[i]
 * @param {{grammar?: string|{open:string,close:string}}} [opts]
 * @returns {{texts: string[], mapping: {byPlaceholder: Map<string,string>, grammar: object}}}
 */
export function pseudonymize(texts, spans, opts = {}) {
  if (!Array.isArray(texts) || !Array.isArray(spans) || texts.length !== spans.length
    || texts.some((t) => typeof t !== 'string') || spans.some((s) => !Array.isArray(s))) {
    throw fail('pii_invalid_input', 'texts and spans must be parallel arrays');
  }
  const grammar = grammarOf(opts.grammar);
  const pattern = placeholderPattern(grammar);

  // Collision safety: never issue a placeholder the input already contains,
  // so a user's literal "[PERSON_1]" is never "restored" into someone's name.
  const taken = new Set();
  for (const t of texts) for (const m of t.matchAll(pattern)) taken.add(m[0]);

  const merged = texts.map((t, i) => mergeSpans(t, spans[i]));
  const byKey = new Map();
  const byPlaceholder = new Map();
  const counters = new Map();

  const placeholderFor = (cls, surface) => {
    const key = surfaceKey(cls, surface);
    if (!key) return null;
    let ph = byKey.get(key);
    if (ph) return ph;
    let n = counters.get(cls) ?? 0;
    do {
      n += 1;
      ph = `${grammar.open}${cls}_${n}${grammar.close}`;
    } while (taken.has(ph));
    counters.set(cls, n);
    byKey.set(key, ph);
    byPlaceholder.set(ph, surface);
    return ph;
  };

  const out = texts.map((text, i) => {
    let res = '';
    let pos = 0;
    for (const s of merged[i]) {
      const ph = placeholderFor(s.cls, text.slice(s.start, s.end));
      if (!ph) continue;
      res += text.slice(pos, s.start) + ph;
      pos = s.end;
    }
    return res + text.slice(pos);
  });

  return { texts: out, mapping: { byPlaceholder, grammar } };
}
