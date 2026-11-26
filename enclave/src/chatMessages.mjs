// Anthropic Messages ⇄ OpenAI chat-completions translation for a direct
// candidate that speaks only the chat wire on the /v1/messages relay — Venice
// (#480), whose `venice/*` models have no OpenRouter twin, so before this a
// Claude Code session on one was refused with "not available on this
// endpoint".
//
//   request : projected /messages body ──messagesToChatRequest──▶ chat payload
//             (then the chat path's own gate, projection and Venice shaping,
//             upstreams.mjs buildMessagesChatBody — one set of provider rules)
//   response: chat SSE chunks ──ChatToMessagesSse──▶ Anthropic SSE
//             one chat.completion ──ChatJsonToMessages──▶ one Message
//
// Same contract as responsesMessages.mjs: the shared /messages gate and
// projection have already run, so this module only checks its own residue — a
// projected field the chat wire cannot express skips the CANDIDATE
// (`unmappable_field`), never the request.
import { randomBytes } from 'node:crypto';
import { MAX_PENDING_CHARS } from './responsesMessages.mjs';

/**
 * The projected /messages fields this translator can express. Every entry of
 * eligibility.mjs ALLOWED_MESSAGES_FIELDS is listed so a field added there
 * later cannot reach this wire without a decision. Mapping:
 *
 *  - temperature / top_p / top_k / max_tokens: same name on the chat wire.
 *  - stop_sequences → stop (at most four, the OpenAI-compatible limit).
 *  - metadata: DROPPED (Anthropic's tracking id; no chat equivalent sent).
 *  - context_management: DROPPED, as OpenRouter does for a non-Anthropic model.
 *  - thinking / output_config.effort: DROPPED. There is no portable chat
 *    knob, and a reasoning_effort the row does not take is a 400; the model
 *    reasons at its default. output_config.format (structured output) SKIPS.
 *  - service_tier: row-originated on the /messages projection; the chat
 *    projection sets it again from the row.
 */
export const MESSAGES_CHAT_MAPPABLE_FIELDS = new Set([
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
  'service_tier',
]);

const MAX_STOP_SEQUENCES = 4;
/** Members a custom (client) tool definition may carry. */
const TOOL_KEYS = new Set(['type', 'name', 'description', 'input_schema', 'cache_control']);

const skip = (reason, offendingField) => (offendingField ? { skip: reason, offendingField } : { skip: reason });

/** tool_result content (string | text blocks) → the tool message's string, or null. */
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
 * One /messages turn → chat messages, appended to `out`. Returns a skip field
 * on a shape we did not clear, else null.
 *
 * A user turn's tool_result blocks become `tool` messages placed FIRST: the
 * chat wire requires them directly after the assistant turn whose tool_calls
 * they answer, and Claude Code puts its text (system reminders) beside them in
 * the same user turn. Its text and images follow as one user message.
 *
 * A `system` entry becomes a chat system message in place. Any other role
 * skips.
 */
function appendTurn(message, out) {
  const role = message?.role;
  if (role !== 'user' && role !== 'assistant' && role !== 'system') return 'messages.role';
  const blocks = typeof message.content === 'string' ? [{ type: 'text', text: message.content }] : message.content;
  if (!Array.isArray(blocks)) return 'messages.content';

  if (role === 'system') {
    // Claude Code sends its environment block as a `system` entry inside
    // messages[] (#493). The chat wire takes one at any position, so it stays
    // where the caller put it; text only, like the top-level `system`.
    const texts = [];
    for (const block of blocks) {
      if (block?.type !== 'text' || typeof block.text !== 'string') return 'messages.content';
      if (block.text !== '') texts.push(block.text);
    }
    if (texts.length > 0) out.push({ role: 'system', content: texts.join('\n\n') });
    return null;
  }

  if (role === 'assistant') {
    const texts = [];
    const toolCalls = [];
    for (const block of blocks) {
      switch (block?.type) {
        case 'text':
          if (typeof block.text !== 'string') return 'messages.content';
          if (block.text !== '') texts.push(block.text);
          break;
        case 'tool_use':
          if (typeof block.id !== 'string' || typeof block.name !== 'string') return 'messages.content';
          toolCalls.push({
            id: block.id,
            type: 'function',
            function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
          });
          break;
        case 'thinking':
        case 'redacted_thinking':
          // Prior-turn thinking is DROPPED: its signature means nothing to
          // another model (responsesMessages.mjs's posture).
          break;
        default:
          return 'messages.content';
      }
    }
    // A turn that carried only thinking leaves nothing to send; dropping it
    // is what the model would have seen of it anyway.
    if (texts.length === 0 && toolCalls.length === 0) return null;
    const turn = { role: 'assistant', content: texts.length > 0 ? texts.join('\n\n') : null };
    if (toolCalls.length > 0) turn.tool_calls = toolCalls;
    out.push(turn);
    return null;
  }

  const tools = [];
  const parts = [];
  for (const block of blocks) {
    switch (block?.type) {
      case 'text':
        if (typeof block.text !== 'string') return 'messages.content';
        if (block.text !== '') parts.push({ type: 'text', text: block.text });
        break;
      case 'image': {
        // The /messages gate admitted it (user turn, image-capable row,
        // base64 jpeg/png/webp); the chat gate re-checks the data URI against
        // the row and Venice's own per-message image limit.
        const source = block.source;
        if (source?.type !== 'base64' || typeof source.media_type !== 'string' || typeof source.data !== 'string') {
          return 'messages.content';
        }
        parts.push({ type: 'image_url', image_url: { url: `data:${source.media_type};base64,${source.data}` } });
        break;
      }
      case 'tool_result': {
        if (typeof block.tool_use_id !== 'string') return 'messages.content';
        const text = toolResultText(block.content);
        if (text === null) return 'messages.content';
        // The chat wire has no error flag on a tool message; say it in-band so
        // the model is not told a failed call succeeded.
        tools.push({ role: 'tool', tool_call_id: block.tool_use_id, content: block.is_error === true ? `Error: ${text}` : text });
        break;
      }
      default:
        return 'messages.content';
    }
  }
  out.push(...tools);
  if (parts.length > 0) {
    const textOnly = parts.every((p) => p.type === 'text');
    out.push({ role: 'user', content: textOnly && parts.length === 1 ? parts[0].text : parts });
  }
  return null;
}

/**
 * Projected /messages body → a chat-completions payload, or a skip. Never
 * mutates `projected` (its nested objects are shared with the caller's body).
 * The result is a PAYLOAD, not the wire body: the caller runs the chat gate
 * and projection on it, which pin the row's model, usage reporting on a
 * stream, and the provider's own parameters.
 *
 * @returns {{ payload: object } | { skip: string, offendingField?: string }}
 */
export function messagesToChatRequest(projected) {
  for (const key of Object.keys(projected)) {
    if (!MESSAGES_CHAT_MAPPABLE_FIELDS.has(key)) return skip('unmappable_field', key);
  }

  const oc = projected.output_config;
  if (oc !== undefined && oc !== null) {
    if (typeof oc !== 'object' || Array.isArray(oc)) return skip('unmappable_field', 'output_config');
    for (const key of Object.keys(oc)) {
      if (key !== 'effort') return skip('unmappable_field', `output_config.${key.slice(0, 40)}`);
    }
  }

  const messages = [];
  const system = projected.system;
  if (typeof system === 'string') {
    if (system !== '') messages.push({ role: 'system', content: system });
  } else if (Array.isArray(system)) {
    const text = system
      .filter((b) => b?.type === 'text' && typeof b.text === 'string' && b.text !== '')
      .map((b) => b.text)
      .join('\n\n');
    if (text !== '') messages.push({ role: 'system', content: text });
  } else if (system !== undefined && system !== null) {
    return skip('unmappable_field', 'system');
  }

  for (const message of Array.isArray(projected.messages) ? projected.messages : []) {
    const bailField = appendTurn(message, messages);
    if (bailField) return skip('unmappable_field', bailField);
  }
  if (!messages.some((m) => m.role === 'user' || m.role === 'tool')) return skip('unmappable_field', 'messages');

  const payload = { model: projected.model, messages, stream: projected.stream === true };
  if (typeof projected.max_tokens === 'number') payload.max_tokens = projected.max_tokens;
  for (const key of ['temperature', 'top_p', 'top_k']) {
    if (projected[key] !== undefined && projected[key] !== null) payload[key] = projected[key];
  }

  const stops = projected.stop_sequences;
  if (stops !== undefined && stops !== null) {
    if (!Array.isArray(stops) || stops.some((s) => typeof s !== 'string')) return skip('unmappable_field', 'stop_sequences');
    if (stops.length > MAX_STOP_SEQUENCES) return skip('unmappable_field', 'stop_sequences');
    if (stops.length > 0) payload.stop = stops;
  }

  if (Array.isArray(projected.tools) && projected.tools.length > 0) {
    const tools = [];
    for (const tool of projected.tools) {
      if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') return skip('unmappable_field', 'tools');
      // Dated server tools were skipped at the gate; only client tools map.
      if (tool.type !== undefined && tool.type !== 'custom') return skip('unmappable_field', 'tools.type');
      for (const key of Object.keys(tool)) {
        if (!TOOL_KEYS.has(key)) return skip('unmappable_field', `tools.${key.slice(0, 40)}`);
      }
      const fn = { name: tool.name, parameters: tool.input_schema ?? { type: 'object', properties: {} } };
      if (typeof tool.description === 'string' && tool.description !== '') fn.description = tool.description;
      tools.push({ type: 'function', function: fn });
    }
    payload.tools = tools;

    const choice = projected.tool_choice;
    if (choice !== undefined && choice !== null) {
      if (typeof choice !== 'object' || Array.isArray(choice)) return skip('unmappable_field', 'tool_choice');
      for (const key of Object.keys(choice)) {
        if (key !== 'type' && key !== 'name' && key !== 'disable_parallel_tool_use') {
          return skip('unmappable_field', 'tool_choice');
        }
      }
      if (choice.type === 'auto') payload.tool_choice = 'auto';
      else if (choice.type === 'any') payload.tool_choice = 'required';
      else if (choice.type === 'none') payload.tool_choice = 'none';
      else if (choice.type === 'tool' && typeof choice.name === 'string') {
        payload.tool_choice = { type: 'function', function: { name: choice.name } };
      } else return skip('unmappable_field', 'tool_choice');
      if (choice.disable_parallel_tool_use === true) payload.parallel_tool_calls = false;
    }
  }

  return { payload };
}

/** chat finish_reason → Anthropic stop_reason. */
function stopReasonFor(finishReason, sawToolUse) {
  if (finishReason === 'length') return 'max_tokens';
  if (finishReason === 'content_filter') return 'refusal';
  if (sawToolUse || finishReason === 'tool_calls' || finishReason === 'function_call') return 'tool_use';
  return 'end_turn';
}

/**
 * chat usage → Anthropic's ADDITIVE convention (input excludes both cache
 * buckets), which is how hp prices every Messages-endpoint settle (hp #1144).
 * The chat wire reports the cache buckets as SUBSETS of prompt_tokens; the
 * field names are the ones cost.mjs reads on the chat path. Clamped so a
 * provider semantics change degrades toward over-charge, never negative.
 */
export function anthropicUsageFromChat(usage) {
  const u = usage && typeof usage === 'object' ? usage : {};
  const prompt = Number(u.prompt_tokens ?? 0) || 0;
  const output = Number(u.completion_tokens ?? 0) || 0;
  const read = Number(u.prompt_tokens_details?.cached_tokens ?? u.cache_read_input_tokens ?? 0) || 0;
  const write = Number(u.prompt_tokens_details?.cache_write_tokens ?? u.cache_creation_input_tokens ?? 0) || 0;
  return {
    input_tokens: Math.max(0, prompt - read - write),
    output_tokens: output,
    cache_read_input_tokens: read,
    cache_creation_input_tokens: write,
  };
}

/** An upstream error object's message, bounded and never echoing structure. */
function upstreamErrorText(err) {
  const m = typeof err === 'string' ? err : err?.message;
  return typeof m === 'string' && m !== '' ? m.slice(0, 300) : 'stream error';
}

/**
 * How long a stream may carry only reasoning (which is not relayed) before a
 * `ping` goes out, so a long think is not a silent connection to the client
 * or to the load balancer in front of it (#411 is the NLB's idle cut).
 */
export const REASONING_PING_MS = 15_000;

/**
 * OpenAI chat-completions SSE → Anthropic Messages SSE.
 *
 * feed(chunk) returns the bytes safe to forward now; finish() closes a stream
 * that ended without `[DONE]` (cleanly when a finish_reason was seen, else as
 * an error event). An upstream `error` chunk or a malformed frame becomes a
 * terminal Anthropic `error` event, after which the transform goes silent.
 *
 * Text deltas stream as a `text` block; each tool call streams as a
 * `tool_use` block, opened once its arguments begin (a name may arrive in
 * fragments before that), its argument fragments as
 * `input_json_delta`. Content blocks cannot interleave on the Anthropic wire,
 * so a fragment for a tool call whose block is already closed ends the stream
 * as an error rather than being silently lost (chat servers emit calls one
 * after another; this has not been seen on Venice). Reasoning deltas are not
 * relayed (the direct paths' posture), but keep the connection alive with
 * `ping`.
 *
 * message_start carries the WIRE model the provider echoed (the first chunk's
 * `model`), for hp's served-model tripwire; the relay's ModelKeyRewriter maps
 * it to the public slug for the client. Usage arrives on the last chunk
 * (`stream_options.include_usage`, pinned by the chat projection) and is
 * emitted on message_delta just before message_stop.
 */
export class ChatToMessagesSse {
  constructor({ upstreamModel, now = Date.now } = {}) {
    this.model = upstreamModel;
    this.now = now;
    this.id = `msg_${randomBytes(12).toString('hex')}`;
    this.buffer = '';
    this.eventData = [];
    this.pendingChars = 0;
    this.started = false;
    this.nextIndex = 0;
    /** The content block currently open: { index, kind: 'text'|'tool', key? }. */
    this.open = null;
    /** chat tool_calls[].index → { index?, id, name, args, opened, closed, sent } */
    this.tools = new Map();
    this.sawToolUse = false;
    this.refused = false;
    this.finishReason = null;
    this.usage = null;
    this.done = false;
    this.fatal = false;
    this.decoder = new TextDecoder();
    this.wireModel = undefined;
    this.lastEmit = now();
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
        model: this.wireModel ?? this.model,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 },
      },
    });
  }

  _close() {
    if (!this.open) return '';
    let out = '';
    if (this.open.kind === 'tool') {
      const entry = this.tools.get(this.open.key);
      // A call with no arguments at all still has to parse as an object.
      if (entry && entry.sent === '') {
        out += this._event('content_block_delta', { index: entry.index, delta: { type: 'input_json_delta', partial_json: '{}' } });
      }
      if (entry) entry.closed = true;
    }
    out += this._event('content_block_stop', { index: this.open.index });
    this.open = null;
    return out;
  }

  /** Open every held call that has a name, in index order (before other output). */
  _flushTools() {
    let out = '';
    for (const [key, entry] of [...this.tools.entries()].sort((a, b) => a[0] - b[0])) {
      if (!entry.opened && entry.name !== '') out += this._openTool(key, entry);
    }
    return out;
  }

  _openTool(key, entry) {
    let out = this._close();
    if (entry.id === '') entry.id = `toolu_${randomBytes(12).toString('hex')}`;
    entry.index = this.nextIndex++;
    entry.opened = true;
    this.open = { index: entry.index, kind: 'tool', key };
    this.sawToolUse = true;
    out += this._event('content_block_start', {
      index: entry.index,
      content_block: { type: 'tool_use', id: entry.id, name: entry.name, input: {} },
    });
    if (entry.args !== '') {
      entry.sent += entry.args;
      out += this._event('content_block_delta', { index: entry.index, delta: { type: 'input_json_delta', partial_json: entry.args } });
      entry.args = '';
    }
    return out;
  }

  _toolDelta(tc) {
    const key = Number.isInteger(tc?.index) ? tc.index : 0;
    let entry = this.tools.get(key);
    if (!entry) {
      entry = { index: undefined, id: '', name: '', args: '', sent: '', opened: false, closed: false };
      this.tools.set(key, entry);
    }
    const fn = tc?.function ?? {};
    const fragment = typeof fn.arguments === 'string' ? fn.arguments : '';
    if (entry.closed) {
      // Nothing new: some servers repeat an empty delta for a finished call.
      if (fragment === '' && !fn.name) return '';
      return this._error('upstream interleaved tool call fragments');
    }
    if (!entry.opened) {
      if (typeof tc?.id === 'string' && tc.id !== '') entry.id = tc.id;
      // A name may arrive in fragments; the block is held until the
      // arguments begin (or something else must be emitted, _flushTools), so
      // the name in content_block_start is the whole one.
      if (typeof fn.name === 'string' && fn.name !== '') entry.name += fn.name;
      entry.args += fragment;
      if (entry.name === '' || entry.args === '') return '';
      let out = '';
      for (const [k, other] of [...this.tools.entries()].sort((a, b) => a[0] - b[0])) {
        if (k !== key && !other.opened && other.name !== '') out += this._openTool(k, other);
      }
      return out + this._openTool(key, entry);
    }
    if (this.open?.kind !== 'tool' || this.open.key !== key) {
      if (fragment === '') return '';
      return this._error('upstream interleaved tool call fragments');
    }
    if (fragment === '') return '';
    entry.sent += fragment;
    return this._event('content_block_delta', { index: entry.index, delta: { type: 'input_json_delta', partial_json: fragment } });
  }

  _complete() {
    let out = this._start() + this._flushTools() + this._close();
    // A call whose name never arrived cannot be shown as a tool_use; failing
    // loudly beats a turn that silently lost the call it made.
    for (const entry of this.tools.values()) {
      if (!entry.opened) return out + this._error('upstream tool call without a name');
    }
    out += this._event('message_delta', {
      delta: { stop_reason: this.refused ? 'refusal' : stopReasonFor(this.finishReason, this.sawToolUse), stop_sequence: null },
      usage: anthropicUsageFromChat(this.usage),
    });
    out += this._event('message_stop', {});
    this.done = true;
    return out;
  }

  /** @param {Buffer|Uint8Array} chunk @returns {Buffer} */
  feed(chunk) {
    if (this.fatal || this.done) return Buffer.alloc(0);
    this.buffer += this.decoder.decode(chunk, { stream: true });
    let out = '';
    this.reasoned = false;
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
    const t = this.now();
    if (out === '' && this.reasoned && this.started && !this.fatal && !this.done && t - this.lastEmit >= REASONING_PING_MS) {
      out = this._event('ping', {});
    }
    if (out !== '') this.lastEmit = t;
    return Buffer.from(out, 'utf8');
  }

  _dispatch(data) {
    // `[DONE]` is only a clean end after a finish_reason: a stream cut
    // mid-generation that still writes the sentinel is a failed answer.
    if (data === '[DONE]') {
      if (this.finishReason === null) return this._start() + this._close() + this._error('upstream stream ended unexpectedly');
      return this._complete();
    }
    let chunk;
    try {
      chunk = JSON.parse(data);
    } catch {
      return this._error('upstream stream frame was not JSON');
    }
    if (!chunk || typeof chunk !== 'object' || Array.isArray(chunk)) return this._error('upstream stream frame was not an object');
    if (chunk.error) return this._start() + this._close() + this._error(`upstream ${upstreamErrorText(chunk.error)}`);

    let out = this._start(chunk.model);
    if (chunk.usage && typeof chunk.usage === 'object') this.usage = chunk.usage;
    const choice = Array.isArray(chunk.choices) ? chunk.choices.find((c) => (c?.index ?? 0) === 0) : undefined;
    if (!choice) return out;
    const delta = choice.delta ?? {};

    if (
      (typeof delta.reasoning_content === 'string' && delta.reasoning_content !== '') ||
      (typeof delta.reasoning === 'string' && delta.reasoning !== '')
    ) {
      this.reasoned = true;
    }

    // A refusal is the model's answer: shown as text, stop_reason 'refusal'
    // (the Responses translator's shape for it).
    if (typeof delta.refusal === 'string' && delta.refusal !== '') this.refused = true;
    const text = [delta.content, delta.refusal].filter((t) => typeof t === 'string' && t !== '').join('');
    if (text !== '') {
      out += this._flushTools();
      if (!this.open || this.open.kind !== 'text') {
        out += this._close();
        const index = this.nextIndex++;
        this.open = { index, kind: 'text' };
        out += this._event('content_block_start', { index, content_block: { type: 'text', text: '' } });
      }
      out += this._event('content_block_delta', { index: this.open.index, delta: { type: 'text_delta', text } });
    }

    if (Array.isArray(delta.tool_calls)) {
      for (const tc of delta.tool_calls) {
        out += this._toolDelta(tc);
        if (this.fatal) return out;
      }
    }

    if (typeof choice.finish_reason === 'string' && choice.finish_reason !== '') {
      this.finishReason = choice.finish_reason;
      out += this._flushTools() + this._close();
    }
    return out;
  }

  /** @returns {Buffer} */
  finish() {
    if (this.fatal || this.done) return Buffer.alloc(0);
    // No `[DONE]`: a stream that reached its finish_reason is complete (some
    // servers omit the sentinel); one that did not is cut, and says so.
    if (this.finishReason !== null) return Buffer.from(this._complete(), 'utf8');
    return Buffer.from(this._start() + this._close() + this._error('upstream stream ended unexpectedly'), 'utf8');
  }
}

/**
 * One NON-streaming chat.completion → one Anthropic Message: the same mapping
 * as the stream, collapsed. Tool-call arguments are parsed (`{}` when
 * unparseable). An `error` member, or a body with no choice, becomes
 * Anthropic's `error` object.
 */
export function chatJsonToMessage(body, { upstreamModel }) {
  const error = (message) => ({ type: 'error', error: { type: 'api_error', message } });
  if (!body || typeof body !== 'object' || Array.isArray(body)) return error('upstream response was not a chat completion');
  if (body.error) return error(`upstream ${upstreamErrorText(body.error)}`);
  const choice = Array.isArray(body.choices) ? body.choices.find((c) => (c?.index ?? 0) === 0) : undefined;
  if (!choice || typeof choice.message !== 'object' || choice.message === null) {
    return error('upstream response carried no choice');
  }
  const msg = choice.message;
  const content = [];
  if (typeof msg.content === 'string' && msg.content !== '') content.push({ type: 'text', text: msg.content });
  const refused = typeof msg.refusal === 'string' && msg.refusal !== '';
  if (refused) content.push({ type: 'text', text: msg.refusal });
  let sawToolUse = false;
  for (const tc of Array.isArray(msg.tool_calls) ? msg.tool_calls : []) {
    const fn = tc?.function ?? {};
    let input = {};
    if (typeof fn.arguments === 'string' && fn.arguments !== '') {
      try {
        const parsed = JSON.parse(fn.arguments);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) input = parsed;
      } catch {
        input = {};
      }
    }
    sawToolUse = true;
    content.push({
      type: 'tool_use',
      id: typeof tc?.id === 'string' && tc.id !== '' ? tc.id : `toolu_${randomBytes(12).toString('hex')}`,
      name: typeof fn.name === 'string' ? fn.name : '',
      input,
    });
  }
  return {
    id: `msg_${randomBytes(12).toString('hex')}`,
    type: 'message',
    role: 'assistant',
    model: typeof body.model === 'string' && body.model !== '' ? body.model : upstreamModel,
    content,
    stop_reason: refused ? 'refusal' : stopReasonFor(choice.finish_reason, sawToolUse),
    stop_sequence: null,
    usage: anthropicUsageFromChat(body.usage),
  };
}

/**
 * The non-streaming twin of ChatToMessagesSse for the dialect relay: feed()
 * buffers the one chat.completion (bounded by MAX_PENDING_CHARS), finish()
 * emits the Message — the ResponsesJsonToMessages contract.
 */
export class ChatJsonToMessages {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.contentType = 'application/json';
    this.streaming = false;
    this.wireModel = undefined;
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
          : chatJsonToMessage(parsed, { upstreamModel: this.model });
      if (parsed && typeof parsed.model === 'string') this.wireModel = parsed.model;
    }
    if (out.type === 'error') this.failed = true;
    this.chunks = [];
    return Buffer.from(JSON.stringify(out), 'utf8');
  }
}
