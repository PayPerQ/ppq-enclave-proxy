/**
 * Shared plumbing for the dialect adapters.
 *
 * Adapter contract (chat.mjs, responses.mjs, messages.mjs):
 *   extractTexts(body, policy?) -> refs      refs[i] = { path, text }
 *   applyTexts(body, refs, texts) -> body'   copy of body with texts[i] at refs[i].path
 *   restoreJson(body, mapping) -> body'      non-stream response, tool-call args included
 *   createEventRestorer(mapping) -> { push(event) -> event[], flush() -> event[] }
 *       push() takes one parsed stream event and returns the events to emit,
 *       in order; a held-back tail is emitted as a synthetic delta event just
 *       before the event that closes its field. flush() at end of stream
 *       returns synthetic deltas for anything still held.
 *
 * Inputs are never mutated. Pure: no I/O, no node:* imports.
 */
import { createRestorer, restoreText } from '../restore.mjs';

const nonEmpty = (s) => typeof s === 'string' && s.trim() !== '';

/** Push a ref when `value` is a non-empty string. */
export function addRef(refs, path, value) {
  if (nonEmpty(value)) refs.push({ path, text: value });
}

/** Refs for every non-empty string leaf of an object/array (tool-use inputs). */
export function addLeafRefs(refs, path, value) {
  if (typeof value === 'string') addRef(refs, path, value);
  else if (Array.isArray(value)) value.forEach((v, i) => addLeafRefs(refs, [...path, i], v));
  else if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) addLeafRefs(refs, [...path, k], value[k]);
  }
}

export function applyTexts(body, refs, texts) {
  if (refs.length !== texts.length) throw new Error('refs and texts must be parallel');
  const out = structuredClone(body);
  refs.forEach((ref, i) => {
    let node = out;
    for (const key of ref.path.slice(0, -1)) node = node[key];
    node[ref.path[ref.path.length - 1]] = texts[i];
  });
  return out;
}

/** Restore every string leaf of a value (objects, arrays), returning a copy. */
export function restoreLeaves(value, mapping) {
  if (typeof value === 'string') return restoreText(value, mapping);
  if (Array.isArray(value)) return value.map((v) => restoreLeaves(v, mapping));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = restoreLeaves(value[k], mapping);
    return out;
  }
  return value;
}

/** Restore `obj[field]` in place when it is a string. */
export function restoreField(obj, field, mapping, opts) {
  if (obj && typeof obj[field] === 'string') obj[field] = restoreText(obj[field], mapping, opts);
}

/**
 * One restorer per independent text stream (per choice+field, per content
 * block, …), created lazily, each remembering the metadata needed to build
 * the synthetic delta that carries its held tail.
 */
export function keyedRestorers(mapping) {
  const byKey = new Map();
  return {
    push(key, chunk, { json = false, meta } = {}) {
      let e = byKey.get(key);
      if (!e) {
        e = { r: createRestorer(mapping, { json }), meta };
        byKey.set(key, e);
      }
      if (meta !== undefined) e.meta = meta;
      return e.r.push(chunk);
    },
    /** Flush one key: returns { tail, meta } (tail may be ''). */
    flush(key) {
      const e = byKey.get(key);
      if (!e) return { tail: '', meta: undefined };
      byKey.delete(key);
      return { tail: e.r.flush(), meta: e.meta };
    },
    keys() {
      return [...byKey.keys()];
    },
  };
}
