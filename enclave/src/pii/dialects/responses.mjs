/**
 * Responses dialect (`/v1/responses`). Contract: see common.mjs.
 *
 * Redacted request text: `input` as a string, or input items — `user` /
 * `assistant` messages (string content or input_text / output_text parts),
 * `function_call.arguments`, `function_call_output.output` and resent
 * reasoning summaries. `instructions` and system/developer messages are never
 * redacted unless `policy.includeSystem` accepts them. Images/files untouched.
 *
 * Restored response text: output_text, refusal, function-call arguments
 * (JSON-escaped), reasoning summary/text — in stream deltas, their `.done`
 * events, content parts, output items and the final `response` object.
 */
import { addJsonStringRefs, addRef, applyTexts, keyedRestorers, restoreField } from './common.mjs';

export { applyTexts };

const REDACTED_ROLES = new Set(['user', 'assistant']);
const TEXT_PARTS = new Set(['input_text', 'output_text']);

export function extractTexts(body, policy = {}) {
  const refs = [];
  if (typeof body?.input === 'string') {
    addRef(refs, ['input'], body.input);
    return refs;
  }
  const items = Array.isArray(body?.input) ? body.input : [];
  items.forEach((item, i) => {
    if (!item || typeof item !== 'object') return;
    const base = ['input', i];
    const type = item.type ?? (item.role ? 'message' : undefined);
    if (type === 'message') {
      const pick = REDACTED_ROLES.has(item.role) ? () => true : (t) => Boolean(policy.includeSystem?.(t));
      if (typeof item.content === 'string') {
        if (pick(item.content)) addRef(refs, [...base, 'content'], item.content);
      } else if (Array.isArray(item.content)) {
        item.content.forEach((part, k) => {
          if (TEXT_PARTS.has(part?.type) && typeof part.text === 'string' && pick(part.text)) {
            addRef(refs, [...base, 'content', k, 'text'], part.text);
          }
        });
      }
    } else if (type === 'function_call') {
      addJsonStringRefs(refs, [...base, 'arguments'], item.arguments);
    } else if (type === 'function_call_output') {
      if (typeof item.output === 'string') addRef(refs, [...base, 'output'], item.output);
      else if (Array.isArray(item.output)) {
        item.output.forEach((part, k) => {
          if (part?.type === 'input_text') addRef(refs, [...base, 'output', k, 'text'], part.text);
        });
      }
    } else if (type === 'reasoning' && Array.isArray(item.summary)) {
      item.summary.forEach((s, k) => addRef(refs, [...base, 'summary', k, 'text'], s?.text));
    }
  });
  return refs;
}

function restorePart(part, mapping) {
  restoreField(part, 'text', mapping);
  restoreField(part, 'refusal', mapping);
}

function restoreItem(item, mapping) {
  if (!item || typeof item !== 'object') return;
  if (item.type === 'function_call') restoreField(item, 'arguments', mapping, { json: true });
  if (Array.isArray(item.content)) for (const p of item.content) restorePart(p, mapping);
  if (Array.isArray(item.summary)) for (const s of item.summary) restoreField(s, 'text', mapping);
}

function restoreResponse(resp, mapping) {
  if (Array.isArray(resp?.output)) for (const item of resp.output) restoreItem(item, mapping);
  restoreField(resp, 'output_text', mapping);
}

/** Non-stream response body. */
export function restoreJson(body, mapping) {
  const out = structuredClone(body);
  restoreResponse(out, mapping);
  return out;
}

// Per-stream text channels: `<base>.delta` carries `delta`, `<base>.done`
// repeats the whole text in `done`. `ids` identify the channel and are copied
// onto a synthetic delta.
const CHANNELS = {
  'response.output_text': { done: 'text', ids: ['item_id', 'output_index', 'content_index'] },
  'response.refusal': { done: 'refusal', ids: ['item_id', 'output_index', 'content_index'] },
  'response.function_call_arguments': { done: 'arguments', ids: ['item_id', 'output_index'], json: true },
  'response.reasoning_summary_text': { done: 'text', ids: ['item_id', 'output_index', 'summary_index'] },
  'response.reasoning_text': { done: 'text', ids: ['item_id', 'output_index', 'content_index'] },
};

const channelOf = (type) => {
  const cut = type.lastIndexOf('.');
  const base = type.slice(0, cut);
  const phase = type.slice(cut + 1);
  return CHANNELS[base] && (phase === 'delta' || phase === 'done') ? { base, phase, ch: CHANNELS[base] } : null;
};

/** Streamed Responses events (parsed `data:` payloads). */
export function createEventRestorer(mapping) {
  const kr = keyedRestorers(mapping);
  const keyOf = (base, ch, ev) => [base, ...ch.ids.map((k) => ev[k])].join('\u0000');

  const synthetic = ({ base, ids }, tail, sequence) => ({
    type: `${base}.delta`,
    ...ids,
    delta: tail,
    ...(sequence !== undefined ? { sequence_number: sequence } : {}),
  });

  return {
    push(event) {
      if (!event || typeof event.type !== 'string') return [event];
      const c = channelOf(event.type);
      const ev = structuredClone(event);
      if (c && c.phase === 'delta') {
        if (typeof ev.delta === 'string') {
          const ids = Object.fromEntries(c.ch.ids.filter((k) => ev[k] !== undefined).map((k) => [k, ev[k]]));
          ev.delta = kr.push(keyOf(c.base, c.ch, ev), ev.delta, {
            json: c.ch.json,
            meta: { base: c.base, ids, sequence: ev.sequence_number },
          });
        }
        return [ev];
      }
      if (c && c.phase === 'done') {
        const { tail, meta } = kr.flush(keyOf(c.base, c.ch, ev));
        restoreField(ev, c.ch.done, mapping, { json: c.ch.json });
        return tail ? [synthetic(meta, tail, ev.sequence_number), ev] : [ev];
      }
      if (ev.part) restorePart(ev.part, mapping);
      if (ev.item) restoreItem(ev.item, mapping);
      if (ev.response) restoreResponse(ev.response, mapping);
      return [ev];
    },
    flush() {
      const out = [];
      for (const key of kr.keys()) {
        const { tail, meta } = kr.flush(key);
        if (tail) out.push(synthetic(meta, tail, meta.sequence));
      }
      return out;
    },
  };
}
