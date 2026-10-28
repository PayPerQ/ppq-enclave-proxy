// Anthropic Messages ⇄ OpenAI Responses translation for a direct candidate
// that speaks the Responses wire — OpenAI first-party (horse-power #1156) —
// what lets a Claude Code session on an OpenAI model (`openai/gpt-5.5` on
// `/v1/messages`) be served by api.openai.com instead of riding OpenRouter.
//
//   request : projected /messages body ──messagesToResponsesRequest──▶ Responses JSON
//   response: Responses SSE events ──ResponsesToMessagesSse──▶ Anthropic SSE
//
// A line-for-line port of horse-power services/directProviders/
// bedrockMessagesTranslator.ts (the hp path has served GPT on /v1/messages
// this way via Bedrock since hp #981); hp's
// enclaveMessagesTranslatorConformance test holds the two identical. The same
// ordering contract as bedrock.mjs: the SHARED gate + projection run first on
// the Messages-shaped body (dated server tools, non-text blocks and unknown
// fields have already skipped there), and this module only checks its own
// residue — a projected field the Responses API cannot express skips the
// CANDIDATE (`unmappable_field`), never the request. OpenRouter still serves.
//
// DIRECT, not composed through chat: Messages→chat→Responses would reuse
// bedrock.mjs but lose `disable_parallel_tool_use` and tool_result error
// flags, and put two lossy hops on every request.
import { randomBytes } from 'node:crypto';

/**
 * The projected /messages fields this translator can express. Everything in
 * eligibility.mjs ALLOWED_MESSAGES_FIELDS is listed, so today nothing skips on
 * NAME here — the list exists so a field added to the shared allowlist later
 * cannot reach this wire without a decision. Mapping decisions:
 *
 *  - temperature / top_p / top_k: DROPPED. The reasoning models 400 on any
 *    non-default temperature or top_p (bedrock.mjs's documented drop), and
 *    top_k has no OpenAI equivalent. OpenRouter's OpenAI endpoints discard
 *    all three, so this reproduces the fallback.
 *  - metadata: DROPPED — Anthropic's `user_id` tracking id. OUR
 *    safety_identifier is set by the dialect's directProject instead.
 *  - context_management: DROPPED. Anthropic's server-side context editing has
 *    no Responses equivalent; OpenRouter cannot apply it to an OpenAI model
 *    either.
 *  - stop_sequences: forwarded nowhere — Responses has no stop sequences, so
 *    a non-empty list SKIPS.
 *  - thinking / output_config: → reasoning.effort (see reasoningEffortFor).
 */
export const MESSAGES_RESPONSES_MAPPABLE_FIELDS = new Set([
  'model',
  'messages',
  'system',
  'stream',
  'max_tokens',
  'temperature',
  'top_p',
  'top_k',
  'stop_sequences',
  'tools',
  'tool_choice',
  'metadata',
  'thinking',
  'context_management',
  'output_config',
  'service_tier', // row-originated; forwarded only for API-valid values
]);

const RESPONSES_SERVICE_TIERS = new Set(['auto', 'default', 'flex', 'priority']);

/**
 * The most the response translation will hold while waiting for a line end or
 * an event's blank line. The relay's own per-line cap (GHSA-33j5-hgc8-9mgg
 * F-03) runs on the TRANSLATED frames, after this transform, so without a cap
 * here a line that never ends would grow the worker's heap unbounded. Same
 * figure as the relay's response buffer (messages.mjs MAX_RESPONSE_BYTES).
 * Over it, the stream ends as a terminal error event (a failed answer the
 * relay still settles). Mirror of hp bedrockMessagesTranslator.ts.
 */
export const MAX_PENDING_CHARS = 4 * 1024 * 1024;

/**
 * Anthropic `output_config.effort` values that pass straight through: the
 * GPT-6 family accepts all five as `reasoning.effort` (probed 2026-09-28 —
 * astra takes low/medium/high/xhigh/max, luna additionally `none`).
 */
const EFFORT_VALUES = new Set(['low', 'medium', 'high', 'xhigh', 'max']);
/** Members a custom (client) tool definition may carry. */
const TOOL_KEYS = new Set(['type', 'name', 'description', 'input_schema', 'cache_control']);

const skip = (reason, offendingField) => (offendingField ? { skip: reason, offendingField } : { skip: reason });

/**
 * The reasoning effort to request, or a skip. `output_config.effort` wins
 * over a thinking budget (the more direct signal — the Anthropic normalizer's
 * rule). A budget maps through the shared buckets of
 * canonicalizeReasoningObject (≤2048 low, ≤8192 medium, else high).
 * `adaptive` means "the model decides" — no effort sent, the model default.
 * `disabled` SKIPS: astra rejects `effort: 'none'` (probed), and silently
 * reasoning anyway would be worse than OpenRouter honoring the "off".
 */
function reasoningEffortFor(projected) {
  const oc = projected.output_config;
  if (oc !== undefined && oc !== null) {
    if (typeof oc !== 'object' || Array.isArray(oc)) return { bail: 'output_config' };
    for (const key of Object.keys(oc)) {
      // `format` is structured output — a different contract, unprobed here.
      if (key !== 'effort') return { bail: `output_config.${key.slice(0, 40)}` };
    }
    if (oc.effort !== undefined) {
      if (!EFFORT_VALUES.has(oc.effort)) return { bail: 'output_config.effort' };
      return { effort: oc.effort };
    }
  }
  const thinking = projected.thinking;
  if (thinking === undefined || thinking === null) return {};
  if (typeof thinking !== 'object' || Array.isArray(thinking)) return { bail: 'thinking' };
  for (const key of Object.keys(thinking)) {
    if (key !== 'type' && key !== 'budget_tokens') return { bail: `thinking.${key.slice(0, 40)}` };
  }
  if (thinking.type === 'adaptive') return {};
  if (thinking.type === 'enabled') {
    const budget = thinking.budget_tokens;
    if (!Number.isInteger(budget) || budget <= 0) return { bail: 'thinking.budget_tokens' };
    if (budget <= 2048) return { effort: 'low' };
    if (budget <= 8192) return { effort: 'medium' };
    return { effort: 'high' };
  }
  return { bail: `thinking.${typeof thinking.type === 'string' ? thinking.type.slice(0, 40) : 'type'}` };
}

/** tool_result content (string | text blocks) → the function_call_output string, or null. */
function toolResultText(content) {
  if (content === undefined || content === null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return null;
  const parts = [];
  for (const block of content) {
    if (block?.type !== 'text' || typeof block.text !== 'string') return null;
    parts.push(block.text);
  }
  return parts.join('');
}

/**
 * One /messages turn → Responses input items, appended to `input`. Returns a
 * skip field on a shape we did not clear, else null.
 *
 * Item order follows block order, because the Responses API requires a
 * function_call_output to follow its function_call and Claude Code puts
 * tool_result blocks FIRST in the user turn that answers them: text is
 * buffered and flushed as its own message whenever a tool item interrupts it.
 */
function appendTurn(message, input) {
  const role = message?.role;
  if (role !== 'user' && role !== 'assistant') return 'messages.role';
  const assistant = role === 'assistant';
  const blocks = typeof message.content === 'string' ? [{ type: 'text', text: message.content }] : message.content;
  if (!Array.isArray(blocks)) return 'messages.content';

  let parts = [];
  const flush = () => {
    if (parts.length > 0) input.push({ role, content: parts });
    parts = [];
  };

  for (const block of blocks) {
    switch (block?.type) {
      case 'text':
        if (typeof block.text !== 'string') return 'messages.content';
        if (block.text !== '') {
          parts.push({ type: assistant ? 'output_text' : 'input_text', text: block.text });
        }
        break;
      case 'image': {
        // The gate admitted this (user turn, image-capable row, base64
        // jpeg/png/webp within Anthropic's 5MB cap) — all three media types
        // the Responses input_image accepts.
        const source = block.source;
        if (assistant || source?.type !== 'base64') return 'messages.content';
        parts.push({ type: 'input_image', image_url: `data:${source.media_type};base64,${source.data}` });
        break;
      }
      case 'tool_use':
        if (!assistant || typeof block.id !== 'string' || typeof block.name !== 'string') {
          return 'messages.content';
        }
        flush();
        input.push({
          type: 'function_call',
          call_id: block.id,
          name: block.name,
          arguments: JSON.stringify(block.input ?? {}),
        });
        break;
      case 'tool_result': {
        if (assistant || typeof block.tool_use_id !== 'string') return 'messages.content';
        const text = toolResultText(block.content);
        if (text === null) return 'messages.content';
        flush();
        input.push({
          type: 'function_call_output',
          call_id: block.tool_use_id,
          // Responses has no error flag on a tool output. Say it in-band so
          // the model is not told a failed call succeeded.
          output: block.is_error === true ? `Error: ${text}` : text,
        });
        break;
      }
      case 'thinking':
      case 'redacted_thinking':
        // Prior-turn thinking is DROPPED — its Anthropic signature means
        // nothing to an OpenAI model, and dropping replayed reasoning is the
        // documented posture of every non-Anthropic translator. Assistant
        // turns only; anywhere else it is a shape we did not clear.
        if (!assistant) return 'messages.content';
        break;
      default:
        return 'messages.content';
    }
  }
  flush();
  return null;
}

/**
 * Projected /messages body → Responses API request body, or a skip. Never
 * mutates `projected` (a shallow copy of the client payload — nested objects
 * are shared with the OpenRouter fallback's body). Returns
 * `{ body }` | `{ skip, offendingField? }`.
 */
export function messagesToResponsesRequest(projected) {
  for (const key of Object.keys(projected)) {
    if (!MESSAGES_RESPONSES_MAPPABLE_FIELDS.has(key)) return skip('unmappable_field', key);
  }
  // Streaming and non-streaming both ride this wire (horse-power #1159): a
  // streaming client gets the Responses SSE translated event by event
  // (ResponsesToMessagesSse); a non-streaming one gets the single Responses
  // object translated to one Message (ResponsesJsonToMessages).
  const streaming = projected.stream === true;

  if (Array.isArray(projected.stop_sequences) ? projected.stop_sequences.length > 0 : projected.stop_sequences !== undefined) {
    return skip('unmappable_field', 'stop_sequences');
  }

  const input = [];
  const system = projected.system;
  if (typeof system === 'string') {
    if (system !== '') input.push({ role: 'system', content: [{ type: 'input_text', text: system }] });
  } else if (Array.isArray(system)) {
    const parts = system
      .filter((b) => b?.type === 'text' && typeof b.text === 'string' && b.text !== '')
      .map((b) => ({ type: 'input_text', text: b.text }));
    if (parts.length > 0) input.push({ role: 'system', content: parts });
  } else if (system !== undefined && system !== null) {
    return skip('unmappable_field', 'system');
  }

  const messages = Array.isArray(projected.messages) ? projected.messages : [];
  for (const message of messages) {
    const bailField = appendTurn(message, input);
    if (bailField) return skip('unmappable_field', bailField);
  }
  if (!input.some((item) => item.role === 'user' || item.type === 'function_call_output')) {
    return skip('unmappable_field', 'messages');
  }

  const body = {
    model: projected.model,
    input,
    stream: streaming,
    // PRIVACY: Responses persists by default; nothing reads a stored response back.
    store: false,
  };
  if (typeof projected.max_tokens === 'number') body.max_output_tokens = projected.max_tokens;
  if (projected.service_tier !== undefined) {
    if (!RESPONSES_SERVICE_TIERS.has(projected.service_tier)) return skip('unmappable_field', 'service_tier');
    body.service_tier = projected.service_tier;
  }
  const reasoning = reasoningEffortFor(projected);
  if (reasoning.bail) return skip('unmappable_field', reasoning.bail);
  if (reasoning.effort) body.reasoning = { effort: reasoning.effort };

  if (Array.isArray(projected.tools) && projected.tools.length > 0) {
    const tools = [];
    for (const tool of projected.tools) {
      if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') return skip('unmappable_field', 'tools');
      // Dated server tools skipped at the gate; a typed tool here is one we
      // have not cleared (only client tools, untyped or `custom`, map).
      if (tool.type !== undefined && tool.type !== 'custom') return skip('unmappable_field', 'tools.type');
      for (const key of Object.keys(tool)) {
        if (!TOOL_KEYS.has(key)) return skip('unmappable_field', `tools.${key.slice(0, 40)}`);
      }
      const flat = {
        type: 'function',
        name: tool.name,
        parameters: tool.input_schema ?? { type: 'object', properties: {} },
        // Anthropic never enforces strict schemas; Responses strict mode 400s
        // on schemas without additionalProperties:false. Preserve the
        // caller's semantics explicitly (bedrock.mjs's rule).
        strict: false,
      };
      if (typeof tool.description === 'string' && tool.description !== '') flat.description = tool.description;
      tools.push(flat);
    }
    body.tools = tools;

    const choice = projected.tool_choice;
    if (choice !== undefined && choice !== null) {
      if (typeof choice !== 'object' || Array.isArray(choice)) return skip('unmappable_field', 'tool_choice');
      for (const key of Object.keys(choice)) {
        if (key !== 'type' && key !== 'name' && key !== 'disable_parallel_tool_use') {
          return skip('unmappable_field', 'tool_choice');
        }
      }
      if (choice.type === 'auto') body.tool_choice = 'auto';
      else if (choice.type === 'any') body.tool_choice = 'required';
      else if (choice.type === 'none') body.tool_choice = 'none';
      else if (choice.type === 'tool' && typeof choice.name === 'string') {
        body.tool_choice = { type: 'function', name: choice.name };
      } else return skip('unmappable_field', 'tool_choice');
      if (choice.disable_parallel_tool_use === true) body.parallel_tool_calls = false;
    }
  }

  return { body };
}

/**
 * Responses API SSE → Anthropic Messages SSE.
 *
 * feed(chunk) returns the bytes safe to forward now; finish() returns an
 * error event for a stream that ended before response.completed. A failure
 * event or malformed frame becomes a terminal Anthropic `error` event, after
 * which the transform goes silent.
 *
 * Event sequence pinned by live traces (2026-09-28, responsesMessages
 * fixtures): response.created → output_item.added (message) →
 * output_text.delta* → output_item.done → output_item.added (function_call)
 * → function_call_arguments.delta* → …arguments.done → output_item.done →
 * response.completed. Reasoning items are not streamed (the chat path's
 * posture): no thinking blocks are emitted.
 *
 * Model identity: message_start carries the WIRE model echoed by the
 * provider (OpenAI: the dated snapshot) — it is the only usage-bearing event
 * with a model, so that is what keeps hp's served-model tripwire honest. The
 * client never sees it: the relay's ModelKeyRewriter maps it to the public
 * slug.
 *
 * Usage: emitted on message_delta in Anthropic's ADDITIVE convention
 * (`input_tokens` excludes both cache buckets), because hp prices every
 * Messages-endpoint settle under that convention (hp #1144) — the subset
 * numbers the provider reported are billed exactly once.
 */
export class ResponsesToMessagesSse {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.id = `msg_${randomBytes(12).toString('hex')}`;
    this.buffer = '';
    this.eventData = [];
    /** Chars of `data:` payload held in eventData, for MAX_PENDING_CHARS. */
    this.pendingChars = 0;
    this.started = false;
    this.nextIndex = 0;
    /** The content block currently open, if any: { index, kind: 'text'|'tool', item }. */
    this.open = null;
    /** function_call item (id or output_index) → { index, sent }. */
    this.tools = new Map();
    this.sawToolUse = false;
    this.done = false;
    this.fatal = false;
    this.decoder = new TextDecoder();
    /** The wire model the stream echoed, for the receipt. */
    this.wireModel = undefined;
  }

  _event(type, payload) {
    return `event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`;
  }

  _error(message) {
    this.fatal = true;
    return this._event('error', { error: { type: 'api_error', message } });
  }

  _start(model) {
    if (this.started) return '';
    this.started = true;
    if (typeof model === 'string' && model !== '') this.wireModel = model;
    return this._event('message_start', {
      message: {
        id: this.id,
        type: 'message',
        role: 'assistant',
        model: typeof model === 'string' && model !== '' ? model : this.model,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 },
      },
    });
  }

  _close() {
    if (!this.open) return '';
    const out = this._event('content_block_stop', { index: this.open.index });
    this.open = null;
    return out;
  }

  _argsSuffix(entry, full) {
    // Defensive backfill: emit only what the deltas never carried. A terminal
    // string that contradicts the streamed prefix is dropped — never corrupt
    // what the client already received (bedrock.mjs's rule).
    if (full.length <= entry.sent.length || !full.startsWith(entry.sent)) return '';
    const suffix = full.slice(entry.sent.length);
    entry.sent = full;
    return this._event('content_block_delta', {
      index: entry.index,
      delta: { type: 'input_json_delta', partial_json: suffix },
    });
  }

  /** @param {Buffer|Uint8Array} chunk @returns {Buffer} */
  feed(chunk) {
    if (this.fatal || this.done) return Buffer.alloc(0);
    this.buffer += this.decoder.decode(chunk, { stream: true });
    let out = '';
    // Scan from a moving start rather than re-slicing the buffer per line: a
    // chunk carrying many lines must not cost quadratic work.
    let start = 0;
    let idx;
    while ((idx = this.buffer.indexOf('\n', start)) !== -1) {
      const line = this.buffer.slice(start, idx).replace(/\r$/, '');
      start = idx + 1;
      if (line === '') {
        if (this.eventData.length > 0) {
          out += this._dispatch(this.eventData.join('\n'));
          this.eventData = [];
          this.pendingChars = 0;
        }
        if (this.fatal || this.done) break;
        continue;
      }
      if (line.startsWith('data:')) {
        const data = line.slice(5).trimStart();
        // Each retained line counts at least one: a run of empty `data:` lines
        // with no blank line between them must hit the cap too (CodeRabbit).
        this.pendingChars += data.length + 1;
        if (this.pendingChars > MAX_PENDING_CHARS) {
          out += this._error('upstream stream event over the size cap');
          break;
        }
        this.eventData.push(data);
      }
    }
    if (this.fatal || this.done) {
      this.buffer = '';
      this.eventData = [];
    } else {
      this.buffer = this.buffer.slice(start);
      if (this.buffer.length > MAX_PENDING_CHARS) {
        out += this._error('upstream stream line over the size cap');
        this.buffer = '';
        this.eventData = [];
      }
    }
    return Buffer.from(out, 'utf8');
  }

  _dispatch(data) {
    if (data === '[DONE]') return '';
    let event;
    try {
      event = JSON.parse(data);
    } catch {
      return this._error('upstream stream frame was not JSON');
    }

    switch (event?.type) {
      case 'response.created':
      case 'response.in_progress':
        return this._start(event.response?.model);

      case 'response.output_item.added': {
        const item = event.item;
        if (item?.type !== 'function_call') return '';
        let out = this._start() + this._close();
        const index = this.nextIndex++;
        const key = item.id ?? event.output_index;
        const entry = { index, sent: '' };
        this.tools.set(key, entry);
        this.open = { index, kind: 'tool', item: key };
        this.sawToolUse = true;
        out += this._event('content_block_start', {
          index,
          content_block: { type: 'tool_use', id: String(item.call_id ?? item.id ?? ''), name: item.name ?? '', input: {} },
        });
        return out;
      }

      case 'response.output_text.delta': {
        if (typeof event.delta !== 'string' || event.delta === '') return '';
        let out = this._start();
        const key = event.item_id ?? event.output_index;
        if (!this.open || this.open.kind !== 'text' || this.open.item !== key) {
          out += this._close();
          const index = this.nextIndex++;
          this.open = { index, kind: 'text', item: key };
          out += this._event('content_block_start', { index, content_block: { type: 'text', text: '' } });
        }
        return out + this._event('content_block_delta', {
          index: this.open.index,
          delta: { type: 'text_delta', text: event.delta },
        });
      }

      case 'response.function_call_arguments.delta': {
        const entry = this.tools.get(event.item_id) ?? this.tools.get(event.output_index);
        if (!entry || typeof event.delta !== 'string' || event.delta === '') return '';
        entry.sent += event.delta;
        return this._event('content_block_delta', {
          index: entry.index,
          delta: { type: 'input_json_delta', partial_json: event.delta },
        });
      }

      case 'response.function_call_arguments.done': {
        const entry = this.tools.get(event.item_id) ?? this.tools.get(event.output_index);
        if (!entry || typeof event.arguments !== 'string') return '';
        return this._argsSuffix(entry, event.arguments);
      }

      case 'response.output_item.done': {
        const item = event.item;
        const key = item?.id ?? event.output_index;
        let out = '';
        if (item?.type === 'function_call' && typeof item.arguments === 'string') {
          const entry = this.tools.get(key);
          if (entry) out += this._argsSuffix(entry, item.arguments);
        }
        if (this.open && this.open.item === key) out += this._close();
        return out;
      }

      case 'response.completed':
      case 'response.incomplete': {
        const response = event.response ?? {};
        const reason = response?.incomplete_details?.reason;
        const stopReason =
          event.type === 'response.incomplete' && reason === 'max_output_tokens'
            ? 'max_tokens'
            : event.type === 'response.incomplete' && reason === 'content_filter'
              ? 'refusal'
              : this.sawToolUse
                ? 'tool_use'
                : 'end_turn';
        let out = this._start(response.model) + this._close();
        const usage = response.usage ?? {};
        const inputTokens = Number(usage.input_tokens ?? 0);
        const outputTokens = Number(usage.output_tokens ?? 0);
        const cacheRead = Number(usage.input_tokens_details?.cached_tokens ?? 0);
        const cacheWrite = Number(usage.input_tokens_details?.cache_write_tokens ?? 0);
        out += this._event('message_delta', {
          delta: { stop_reason: stopReason, stop_sequence: null },
          usage: {
            // The provider reports both cache buckets as SUBSETS of
            // input_tokens; Anthropic's convention excludes them. Clamped so a
            // provider semantics change degrades toward over-charge, never
            // negative.
            input_tokens: Math.max(0, inputTokens - cacheRead - cacheWrite),
            output_tokens: outputTokens,
            cache_read_input_tokens: cacheRead,
            cache_creation_input_tokens: cacheWrite,
          },
        });
        out += this._event('message_stop', {});
        this.done = true;
        return out;
      }

      case 'response.failed': {
        const message = event.response?.error?.message || 'upstream response.failed with no detail';
        return this._start() + this._close() + this._error(`upstream ${message}`);
      }

      case 'error':
        return this._start() + this._close() + this._error(`upstream ${event.message || event.code || 'stream error'}`);

      default:
        return ''; // content_part.*, output_text.done, reasoning items, … — nothing to relay
    }
  }

  /** @returns {Buffer} */
  finish() {
    if (this.fatal || this.done) return Buffer.alloc(0);
    // Ended before response.completed: say so, so the client does not take a
    // partial answer for a complete one.
    return Buffer.from(this._start() + this._close() + this._error('upstream stream ended unexpectedly'), 'utf8');
  }
}

/**
 * One NON-streaming Responses object → one Anthropic Message (horse-power
 * #1159). The same mapping ResponsesToMessagesSse applies event by event,
 * collapsed: output_text parts become one `text` block, function_call items
 * become `tool_use` blocks (arguments parsed, `{}` when unparseable),
 * `status` / `incomplete_details` pick stop_reason, usage is in Anthropic's
 * ADDITIVE convention as on the stream. `model` is the wire echo. An `error`
 * member or a `failed` status becomes Anthropic's `error` object. Mirror of
 * hp bedrockMessagesTranslator.ts responsesJsonToMessage.
 */
export function responsesJsonToMessage(response, { upstreamModel }) {
  const error = (message) => ({ type: 'error', error: { type: 'api_error', message } });
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    return error('upstream response was not a Responses object');
  }
  if (response.error && typeof response.error === 'object') {
    return error(`upstream ${response.error.message || 'response failed'}`);
  }
  if (response.status === 'failed') return error('upstream response failed');
  const content = [];
  let text = '';
  let refusal = '';
  let sawToolUse = false;
  const flushText = () => {
    if (text !== '') content.push({ type: 'text', text });
    text = '';
  };
  for (const item of Array.isArray(response.output) ? response.output : []) {
    if (item?.type === 'message' && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part?.type === 'output_text' && typeof part.text === 'string') text += part.text;
        // A refusal part (the model declined): surfaced as text under
        // stop_reason 'refusal', Anthropic's own shape for it — never a
        // silent empty end_turn (CodeRabbit on #390).
        else if (part?.type === 'refusal' && typeof part.refusal === 'string') refusal += part.refusal;
      }
    } else if (item?.type === 'function_call') {
      flushText();
      sawToolUse = true;
      let input = {};
      if (typeof item.arguments === 'string' && item.arguments !== '') {
        try {
          const parsed = JSON.parse(item.arguments);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) input = parsed;
        } catch {
          input = {};
        }
      }
      content.push({ type: 'tool_use', id: String(item.call_id ?? item.id ?? ''), name: typeof item.name === 'string' ? item.name : '', input });
    }
  }
  flushText();
  if (refusal !== '') content.push({ type: 'text', text: refusal });
  const reason = response.status === 'incomplete' ? response.incomplete_details?.reason : undefined;
  const stopReason =
    reason === 'max_output_tokens'
      ? 'max_tokens'
      : reason === 'content_filter' || refusal !== ''
        ? 'refusal'
        : sawToolUse
          ? 'tool_use'
          : 'end_turn';
  const usage = response.usage ?? {};
  const inputTokens = Number(usage.input_tokens ?? 0);
  const outputTokens = Number(usage.output_tokens ?? 0);
  const cacheRead = Number(usage.input_tokens_details?.cached_tokens ?? 0);
  const cacheWrite = Number(usage.input_tokens_details?.cache_write_tokens ?? 0);
  return {
    id: `msg_${randomBytes(12).toString('hex')}`,
    type: 'message',
    role: 'assistant',
    model: typeof response.model === 'string' && response.model !== '' ? response.model : upstreamModel,
    content,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: {
      input_tokens: Math.max(0, inputTokens - cacheRead - cacheWrite),
      output_tokens: outputTokens,
      cache_read_input_tokens: cacheRead,
      cache_creation_input_tokens: cacheWrite,
    },
  };
}

/**
 * The non-streaming twin of ResponsesToMessagesSse for the dialect relay:
 * feed() buffers the one Responses object (bounded by MAX_PENDING_CHARS),
 * finish() emits the Message. The relay's JSON path then reads the usage off
 * the body it wrote.
 */
export class ResponsesJsonToMessages {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.contentType = 'application/json';
    this.streaming = false;
    this.wireModel = undefined;
    // True once finish() emitted Anthropic's error object instead of a
    // Message (see ResponsesJsonToChat.failed): the relay settles and
    // reports the answer as an upstream failure.
    this.failed = false;
    this.chunks = [];
    this.bytes = 0;
    this.over = false;
    this.done = false;
  }
  feed(chunk) {
    if (this.done || this.over) return Buffer.alloc(0);
    this.bytes += chunk.length;
    if (this.bytes > MAX_PENDING_CHARS) {
      this.over = true;
      this.chunks = [];
      return Buffer.alloc(0);
    }
    this.chunks.push(Buffer.from(chunk));
    return Buffer.alloc(0);
  }
  finish() {
    if (this.done) return Buffer.alloc(0);
    this.done = true;
    let out;
    if (this.over) {
      out = { type: 'error', error: { type: 'api_error', message: 'upstream response body over the size cap' } };
    } else {
      let parsed;
      try {
        parsed = JSON.parse(Buffer.concat(this.chunks).toString('utf8'));
      } catch {
        parsed = undefined;
      }
      out =
        parsed === undefined
          ? { type: 'error', error: { type: 'api_error', message: 'upstream response body was not JSON' } }
          : responsesJsonToMessage(parsed, { upstreamModel: this.model });
      if (parsed && typeof parsed.model === 'string') this.wireModel = parsed.model;
    }
    if (out.type === 'error') this.failed = true;
    this.chunks = [];
    return Buffer.from(JSON.stringify(out), 'utf8');
  }
}
