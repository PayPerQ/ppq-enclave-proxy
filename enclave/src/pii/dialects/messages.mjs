/**
 * Anthropic Messages dialect (`/v1/messages`). Contract: see common.mjs.
 *
 * Redacted request text: `user` / `assistant` message content — string,
 * `text` blocks, `tool_result` content (string or `text` blocks) and every
 * string leaf of a resent `tool_use.input`. The top-level `system` prompt is
 * never redacted. `thinking` / `redacted_thinking` blocks are left untouched in
 * both directions: they are signed by the provider, so rewriting them would
 * break the signature on the next turn. Consequence, accepted by design: the
 * model's thinking may quote placeholders, and those reach the client as-is
 * (never restored). Images and documents are untouched.
 *
 * Restored response text: `text` blocks and `tool_use.input` string leaves;
 * streamed `text_delta` and `input_json_delta` (JSON-escaped).
 */
import { addLeafRefs, addRef, applyTexts, keyedRestorers, restoreField, restoreLeaves } from './common.mjs';

export { applyTexts };

const REDACTED_ROLES = new Set(['user', 'assistant']);

export function extractTexts(body) {
  const refs = [];
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  messages.forEach((m, i) => {
    if (!m || typeof m !== 'object' || !REDACTED_ROLES.has(m.role)) return;
    const base = ['messages', i, 'content'];
    if (typeof m.content === 'string') {
      addRef(refs, base, m.content);
      return;
    }
    if (!Array.isArray(m.content)) return;
    m.content.forEach((block, k) => {
      if (!block || typeof block !== 'object') return;
      if (block.type === 'text') addRef(refs, [...base, k, 'text'], block.text);
      else if (block.type === 'tool_use') addLeafRefs(refs, [...base, k, 'input'], block.input);
      else if (block.type === 'tool_result') {
        if (typeof block.content === 'string') addRef(refs, [...base, k, 'content'], block.content);
        else if (Array.isArray(block.content)) {
          block.content.forEach((b, j) => {
            if (b?.type === 'text') addRef(refs, [...base, k, 'content', j, 'text'], b.text);
          });
        }
      }
    });
  });
  return refs;
}

function restoreBlock(block, mapping) {
  if (!block || typeof block !== 'object') return;
  if (block.type === 'text') restoreField(block, 'text', mapping);
  else if (block.type === 'tool_use' && block.input !== undefined) block.input = restoreLeaves(block.input, mapping);
}

function restoreMessage(msg, mapping) {
  if (Array.isArray(msg?.content)) for (const b of msg.content) restoreBlock(b, mapping);
}

/** Non-stream response body. */
export function restoreJson(body, mapping) {
  const out = structuredClone(body);
  restoreMessage(out, mapping);
  return out;
}

const DELTA_FIELDS = {
  text_delta: { field: 'text', json: false },
  input_json_delta: { field: 'partial_json', json: true },
};

/** Streamed Messages events (parsed `data:` payloads). */
export function createEventRestorer(mapping) {
  const kr = keyedRestorers(mapping);
  const key = (index, type) => `${index}:${type}`;

  const tailsFor = (index) => {
    const out = [];
    for (const k of kr.keys()) {
      if (!k.startsWith(`${index}:`)) continue;
      const { tail, meta } = kr.flush(k);
      if (tail) out.push({ type: 'content_block_delta', index: meta.index, delta: { type: meta.type, [DELTA_FIELDS[meta.type].field]: tail } });
    }
    return out;
  };

  return {
    push(event) {
      if (!event || typeof event.type !== 'string') return [event];
      const ev = structuredClone(event);
      switch (ev.type) {
        case 'content_block_delta': {
          const spec = DELTA_FIELDS[ev.delta?.type];
          if (spec && typeof ev.delta[spec.field] === 'string') {
            ev.delta[spec.field] = kr.push(key(ev.index, ev.delta.type), ev.delta[spec.field], {
              json: spec.json,
              meta: { index: ev.index, type: ev.delta.type },
            });
          }
          return [ev];
        }
        case 'content_block_stop':
          return [...tailsFor(ev.index), ev];
        case 'content_block_start':
          restoreBlock(ev.content_block, mapping);
          return [ev];
        case 'message_start':
          restoreMessage(ev.message, mapping);
          return [ev];
        default:
          return [ev];
      }
    },
    flush() {
      const indices = new Set(kr.keys().map((k) => k.slice(0, k.indexOf(':'))));
      return [...indices].flatMap((i) => tailsFor(i));
    },
  };
}
