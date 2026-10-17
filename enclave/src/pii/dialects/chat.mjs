/**
 * Chat Completions dialect (`/v1/chat/completions`). Contract: see common.mjs.
 *
 * Redacted request text: `user`, `assistant`, `tool` (and legacy `function`)
 * message content — string or `text` parts — plus, on assistant turns being
 * resent, `tool_calls[].function.arguments` and reasoning strings (they were
 * restored on the way out, so they carry cleartext on the way back in).
 * `system` / `developer` text is never redacted unless `policy.includeSystem`
 * accepts it. Images, audio and files are untouched.
 *
 * Restored response text: content, reasoning, reasoning_content, refusal and
 * tool-call arguments (JSON-escaped), streamed and non-streamed.
 */
import { addRef, applyTexts, keyedRestorers, restoreField } from './common.mjs';

export { applyTexts };

const REDACTED_ROLES = new Set(['user', 'assistant', 'tool', 'function']);
const TEXT_FIELDS = ['content', 'reasoning', 'reasoning_content', 'refusal'];
const REASONING_FIELDS = ['reasoning', 'reasoning_content'];

/**
 * @param body   parsed request body
 * @param policy { includeSystem?: (text: string) => boolean }
 */
export function extractTexts(body, policy = {}) {
  const refs = [];
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  messages.forEach((m, i) => {
    if (!m || typeof m !== 'object') return;
    const base = ['messages', i];
    const pick = REDACTED_ROLES.has(m.role) ? () => true : (t) => Boolean(policy.includeSystem?.(t));
    if (typeof m.content === 'string') {
      if (pick(m.content)) addRef(refs, [...base, 'content'], m.content);
    } else if (Array.isArray(m.content)) {
      m.content.forEach((part, k) => {
        if (part?.type === 'text' && typeof part.text === 'string' && pick(part.text)) {
          addRef(refs, [...base, 'content', k, 'text'], part.text);
        }
      });
    }
    if (m.role !== 'assistant') return;
    for (const f of REASONING_FIELDS) addRef(refs, [...base, f], m[f]);
    if (Array.isArray(m.tool_calls)) {
      m.tool_calls.forEach((tc, j) => addRef(refs, [...base, 'tool_calls', j, 'function', 'arguments'], tc?.function?.arguments));
    }
    addRef(refs, [...base, 'function_call', 'arguments'], m.function_call?.arguments);
  });
  return refs;
}

function restoreMessage(m, mapping) {
  if (!m || typeof m !== 'object') return;
  for (const f of TEXT_FIELDS) restoreField(m, f, mapping);
  if (Array.isArray(m.content)) for (const part of m.content) restoreField(part, 'text', mapping);
  if (Array.isArray(m.tool_calls)) for (const tc of m.tool_calls) restoreField(tc?.function, 'arguments', mapping, { json: true });
  restoreField(m.function_call, 'arguments', mapping, { json: true });
}

/** Non-stream response body. */
export function restoreJson(body, mapping) {
  const out = structuredClone(body);
  if (Array.isArray(out?.choices)) for (const c of out.choices) restoreMessage(c?.message, mapping);
  return out;
}

/** Streamed `chat.completion.chunk` events. */
export function createEventRestorer(mapping) {
  const kr = keyedRestorers(mapping);
  let envelope = {};

  // Append every held tail of choice `idx` to `delta` (text fields + tool args).
  const closeChoice = (idx, getDelta) => {
    for (const key of kr.keys()) {
      if (!key.startsWith(`${idx}:`)) continue;
      const { tail, meta } = kr.flush(key);
      if (!tail) continue;
      const delta = getDelta();
      if (meta.kind === 'text') {
        delta[meta.field] = (delta[meta.field] ?? '') + tail;
        continue;
      }
      if (!Array.isArray(delta.tool_calls)) delta.tool_calls = [];
      let tc = delta.tool_calls.find((t) => t?.index === meta.index);
      if (!tc) {
        tc = { index: meta.index, function: { arguments: '' } };
        delta.tool_calls.push(tc);
      }
      tc.function ??= {};
      tc.function.arguments = (tc.function.arguments ?? '') + tail;
    }
  };

  return {
    push(event) {
      if (!event || !Array.isArray(event.choices)) return [event];
      const ev = structuredClone(event);
      envelope = {};
      for (const k of ['id', 'object', 'created', 'model']) if (ev[k] !== undefined) envelope[k] = ev[k];
      ev.choices.forEach((c, pos) => {
        if (!c || typeof c !== 'object') return;
        const idx = c.index ?? pos;
        const d = c.delta;
        if (d && typeof d === 'object') {
          for (const f of TEXT_FIELDS) {
            if (typeof d[f] === 'string') d[f] = kr.push(`${idx}:${f}`, d[f], { meta: { kind: 'text', field: f } });
          }
          if (Array.isArray(d.tool_calls)) {
            d.tool_calls.forEach((tc, j) => {
              if (typeof tc?.function?.arguments !== 'string') return;
              const ti = tc.index ?? j;
              tc.function.arguments = kr.push(`${idx}:tool:${ti}`, tc.function.arguments, { json: true, meta: { kind: 'tool', index: ti } });
            });
          }
        }
        // The choice is finishing: its held tails ride on this chunk's delta,
        // after this chunk's own text, so order is preserved.
        if (c.finish_reason != null) {
          closeChoice(idx, () => {
            if (!c.delta || typeof c.delta !== 'object') c.delta = {};
            return c.delta;
          });
        }
      });
      return [ev];
    },
    flush() {
      const choices = new Map();
      for (const key of kr.keys()) {
        const idx = Number(key.slice(0, key.indexOf(':')));
        if (choices.has(idx)) continue;
        const choice = { index: idx, delta: {}, finish_reason: null };
        closeChoice(idx, () => choice.delta);
        choices.set(idx, choice);
      }
      const live = [...choices.values()].filter((c) => Object.keys(c.delta).length);
      return live.length ? [{ ...envelope, choices: live }] : [];
    },
  };
}
