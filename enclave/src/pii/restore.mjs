/**
 * Placeholder restoration, for whole strings and for chunked streams.
 *
 * Only placeholders issued in THIS request's mapping are restored; anything
 * else that matches the grammar (a user's literal text, a placeholder the
 * model invented) is delivered verbatim. Restoration is single-pass: a
 * restored surface is never scanned again.
 *
 * `json: true` escapes each surface for a JSON string context — for text that
 * is itself JSON (tool-call arguments), where a raw quote or backslash in a
 * surface would corrupt the arguments.
 *
 * Pure: no I/O, no node:* imports (shared with the browser).
 */
import { placeholderPattern } from './core.mjs';

const surfaceFor = (surface, json) => (json ? JSON.stringify(surface).slice(1, -1) : surface);

function replaceAll(text, mapping, pattern, json, stats) {
  let out = '';
  let last = 0;
  pattern.lastIndex = 0;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
    const surface = mapping.byPlaceholder.get(m[0]);
    if (stats) stats[surface === undefined ? 'unknown' : 'restored'] += 1;
    out += text.slice(last, m.index) + (surface === undefined ? m[0] : surfaceFor(surface, json));
    last = m.index + m[0].length;
  }
  return { out, rest: text.slice(last) };
}

/** Restore every issued placeholder in a complete string. */
export function restoreText(text, mapping, { json = false } = {}) {
  if (!mapping.byPlaceholder.size) return text;
  const { out, rest } = replaceAll(text, mapping, placeholderPattern(mapping.grammar), json);
  return out + rest;
}

/**
 * Stateful restorer for a single text stream (one field of one choice/block).
 * push(chunk) returns the text safe to emit now; a trailing run that could
 * still grow into an issued placeholder is held back (never longer than the
 * longest issued placeholder). flush() at end of stream returns whatever is
 * held, as-is — it was not a placeholder, and nothing is dropped.
 */
export function createRestorer(mapping, { json = false } = {}) {
  const stats = { restored: 0, unknown: 0 };
  const issued = [...mapping.byPlaceholder.keys()];
  const prefixes = new Set();
  let maxLen = 0;
  for (const ph of issued) {
    maxLen = Math.max(maxLen, ph.length);
    for (let k = 1; k < ph.length; k++) prefixes.add(ph.slice(0, k));
  }
  const pattern = issued.length ? placeholderPattern(mapping.grammar) : null;
  let carry = '';

  return {
    stats,
    push(chunk) {
      if (!pattern) return chunk;
      const { out, rest } = replaceAll(carry + chunk, mapping, pattern, json, stats);
      carry = '';
      for (let k = Math.min(maxLen - 1, rest.length); k > 0; k--) {
        const tail = rest.slice(rest.length - k);
        if (prefixes.has(tail)) {
          carry = tail;
          return out + rest.slice(0, rest.length - k);
        }
      }
      return out + rest;
    },
    flush() {
      const tail = carry;
      carry = '';
      return tail;
    },
  };
}
