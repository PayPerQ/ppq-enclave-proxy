/**
 * Placeholder restoration, for whole strings and for chunked streams.
 *
 * Only placeholders issued in THIS request's mapping are restored; anything
 * else that matches the grammar (a user's literal text, a placeholder the
 * model invented) is delivered verbatim. Restoration is single-pass: a
 * restored surface is never scanned again.
 *
 * Lenient forms (models do not always copy delimiters faithfully): an issued
 * placeholder is also restored when its delimiters were dropped ("PERSON_1",
 * or only one of them kept) and, in json mode, when a delimiter is written as
 * a \uXXXX escape (hex in either case). A token without both delimiters is
 * word-boundary safe: "PERSON_12" never matches "PERSON_1", "XPERSON_1" and
 * "PERSON_1x" never match. Bare tokens that were not issued ("UTF_8",
 * "PERSON_9") stay verbatim and are not counted as unknown placeholders.
 *
 * `json: true` escapes each surface for a JSON string context — for text that
 * is itself JSON (tool-call arguments), where a raw quote or backslash in a
 * surface would corrupt the arguments.
 *
 * Pure: no I/O, no node:* imports (shared with the browser).
 */
import { grammarOf } from './core.mjs';

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const surfaceFor = (surface, json) => (json ? JSON.stringify(surface).slice(1, -1) : surface);

/** `\uXXXX` escapes of a delimiter in every hex-case spelling ('' if none). */
function escapedVariants(delim) {
  let out = [''];
  for (let i = 0; i < delim.length; i++) {
    const hex = delim.charCodeAt(i).toString(16).padStart(4, '0');
    // JSON hex digits are case-insensitive, per digit
    let forms = [''];
    for (const d of hex) forms = forms.flatMap((f) => [...new Set([d.toLowerCase(), d.toUpperCase()])].map((x) => f + x));
    out = out.flatMap((o) => forms.map((f) => `${o}\\u${f}`));
  }
  return out;
}

const WORD = String.raw`[\p{L}\p{N}_]`;

/** Compiled matchers per mapping (restoreText runs once per JSON leaf). */
const compiled = new WeakMap();

function compile(mapping, json) {
  let entry = compiled.get(mapping);
  if (!entry || entry.size !== mapping.byPlaceholder.size) {
    entry = { size: mapping.byPlaceholder.size };
    compiled.set(mapping, entry);
  }
  const key = json ? 'json' : 'text';
  return (entry[key] ??= build(mapping, json));
}

/**
 * Compile the token matcher for one mapping. Groups: 1 = open delimiter (any
 * spelling), 2 = CLASS_n, 3 = close delimiter. The lookbehind applies only
 * when there is no open delimiter (an escaped one ends in a hex digit); the
 * lookahead is satisfied by any close spelling (none starts with a word char).
 * In json mode a `\n`-style escape right before a bare token is a boundary.
 */
function build(mapping, json) {
  const g = grammarOf(mapping.grammar);
  const opens = [g.open, ...(json ? escapedVariants(g.open) : [])];
  const closes = [g.close, ...(json ? escapedVariants(g.close) : [])];
  const alt = (xs) => xs.map(escapeRe).join('|');
  const before = json ? String.raw`(?:(?<!${WORD})|(?<=\\[bfnrt]))` : `(?<!${WORD})`;
  const re = new RegExp(`(?:(${alt(opens)})|${before})([A-Z]+_[0-9]+)(?!${WORD})(${alt(closes)})?`, 'gu');

  // Every spelling of every issued placeholder; its proper prefixes are what a
  // stream must hold back (a complete bare token is a proper prefix of its
  // closed form, so it is held until the next char proves the boundary).
  const prefixes = new Set();
  let maxLen = 0;
  for (const ph of mapping.byPlaceholder.keys()) {
    const core = ph.slice(g.open.length, ph.length - g.close.length);
    for (const o of ['', ...opens]) {
      for (const c of closes) {
        const tok = o + core + c;
        maxLen = Math.max(maxLen, tok.length);
        for (let k = 1; k < tok.length; k++) prefixes.add(tok.slice(0, k));
      }
    }
  }
  return { g, re, closes, prefixes, maxLen };
}

/**
 * Replace tokens in `text` from `from` on (`text.slice(0, from)` is context
 * only, for the lookbehind). When `final` is false, stop before a token that
 * the next input could still change (no close yet and nothing after it that
 * rules one out); the caller's hold-back scan then keeps it.
 */
function replaceFrom(text, from, c, mapping, json, stats, final) {
  let out = '';
  let last = from;
  c.re.lastIndex = from;
  for (let m = c.re.exec(text); m; m = c.re.exec(text)) {
    const end = m.index + m[0].length;
    if (!final && m[3] === undefined && c.closes.some((cl) => cl.startsWith(text.slice(end)))) {
      return { out, stop: last }; // the hold-back scan keeps the token
    }
    const surface = mapping.byPlaceholder.get(c.g.open + m[2] + c.g.close);
    const bracketed = m[1] !== undefined && m[3] !== undefined;
    if (surface !== undefined) {
      if (stats) stats.restored += 1;
      out += text.slice(last, m.index) + surfaceFor(surface, json);
    } else {
      if (stats && bracketed) stats.unknown += 1;
      out += text.slice(last, end);
    }
    last = end;
  }
  return { out, stop: last };
}

export function restoreText(text, mapping, { json = false } = {}) {
  if (!mapping.byPlaceholder.size) return text;
  const r = createRestorer(mapping, { json });
  return r.push(text) + r.flush();
}

export function createRestorer(mapping, { json = false } = {}) {
  const stats = { restored: 0, unknown: 0 };
  const c = mapping.byPlaceholder.size ? compile(mapping, json) : null;
  let ctx = ''; // original text right before `carry` (lookbehind context)
  let carry = '';
  const run = (chunk, final) => {
    const text = ctx + carry + chunk;
    const from = ctx.length;
    const { out, stop } = replaceFrom(text, from, c, mapping, json, stats, final);
    let rest = text.slice(stop);
    let emitted = out;
    let hold = '';
    if (!final) {
      for (let k = Math.min(c.maxLen - 1, rest.length); k > 0; k--) {
        const tail = rest.slice(rest.length - k);
        if (c.prefixes.has(tail)) { hold = tail; break; }
      }
      rest = rest.slice(0, rest.length - hold.length);
    }
    emitted += rest;
    const holdAt = text.length - hold.length;
    ctx = text.slice(Math.max(0, holdAt - 2), holdAt);
    carry = hold;
    return emitted;
  };
  return {
    stats,
    push(chunk) {
      if (!c) return chunk;
      return run(chunk, false);
    },
    flush() {
      if (!c || !carry) return '';
      const out = run('', true);
      carry = '';
      return out;
    },
  };
}
