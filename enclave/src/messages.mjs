/**
 * `/v1/messages` — the Anthropic Messages dialect, served IN the enclave so a
 * Claude Code session's context is as private as a chat prompt (#275).
 *
 * horse-power serves this route on the enclave-bypass host by forwarding the
 * body AS-IS to OpenRouter's `/api/v1/messages`: no translation, OpenRouter
 * speaks the dialect for every model it carries. The enclave does the same.
 * This module holds the parts that are pure: the validator (only what the
 * enclave itself needs to know), the input measure hp bounds spend with, the
 * usage extraction the settle is built from, the Anthropic error shape, and
 * the `count_tokens` projection. server.mjs owns the handlers (they need the
 * tunnels, EHBP and the settle queue).
 *
 * The Messages wire grammar is already known here: anthropic.mjs speaks it to
 * api.anthropic.com as an UPSTREAM dialect and parses its SSE back into chat
 * chunks. This module parses the same events for a client that speaks the
 * dialect itself, where nothing is translated and the frames go through
 * verbatim; only the numbers are read.
 *
 * Everything returned to hp is a count or a closed value: no content leaves.
 */
import { loadTokenizer, measureInput, TOKENIZE_SLICE_CHARS } from './inputEstimate.mjs';
import { ERROR_CODES } from './errorReport.mjs';
import { providerName } from './providerName.mjs';

/** Where the client posts, and where OpenRouter serves it. */
export const MESSAGES_PATH = '/v1/messages';
export const COUNT_TOKENS_PATH = '/v1/messages/count_tokens';
export const MESSAGES_UPSTREAM_PATH = '/api/v1/messages';
/** Anthropic's own count endpoint; the enclave calls it with its Anthropic key. */
export const COUNT_TOKENS_UPSTREAM_PATH = '/v1/messages/count_tokens';
/** What `/enclave/authorize` learns about the request. */
export const MESSAGES_ENDPOINT = 'messages';
/** On a count_tokens authorize: credential + resolution only, no balance gate (hp services/messagesEndpoint.ts). */
export const COUNT_TOKENS_INTENT = 'count_tokens';
/** `cost_source` on the settle: the usage frame OpenRouter put on the stream. */
export const MESSAGES_COST_SOURCE = 'messages-usage';

/**
 * Anthropic rejects count_tokens bodies over 32 MB with 413 (hp mirrors it);
 * the same cap bounds what one sealed request may ask this worker to hold.
 */
export const MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024;
/** A non-streaming answer is one JSON body; bounded like decisions. */
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

const isPlainRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);


/**
 * Validate a Messages body — only as far as the enclave needs. The body is
 * forwarded verbatim, so OpenRouter and the provider keep their own stricter
 * checks; what is pinned here is what the handler itself reads: the model it
 * authorizes, the `max_tokens` it caps, the `messages` it measures and the
 * `stream` that decides how the answer is metered.
 *
 * Returns `{ kind: 'ok', value: { model, max_tokens, stream } }` or
 * `{ kind: 'invalid', error: { field, message } }`. `max_tokens` is required
 * by the API itself (a body without it is refused upstream with the same
 * message), so refusing it here costs the caller nothing and saves a round
 * trip through authorize.
 */
export function validateMessagesRequest(body) {
  const fail = (field, message) => ({ kind: 'invalid', error: { field, message } });

  if (!isPlainRecord(body)) return fail('body', 'Request body must be a JSON object');

  const { model, messages, max_tokens, stream, system } = body;

  if (typeof model !== 'string' || model.trim() === '') {
    return fail('model', 'Missing required field: model');
  }
  if (!Number.isInteger(max_tokens) || max_tokens < 1) {
    return fail('max_tokens', 'max_tokens: Field required (a positive integer)');
  }
  if (!Array.isArray(messages) || messages.length === 0) {
    return fail('messages', 'messages: Field required (a non-empty array)');
  }
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    const at = `messages.${i}`;
    if (!isPlainRecord(m)) return fail(at, 'Each message must be an object');
    // Any non-empty role string: the body goes to OpenRouter verbatim and it
    // accepts roles beyond `user`/`assistant` (a `system` entry inside
    // `messages` is folded into the system prompt, as it was on the
    // horse-power route this replaced). The handler reads the role only to
    // project the body for the input measure, which copies it through, so
    // the enclave has no stake in which roles the model allows (#282).
    if (typeof m.role !== 'string' || m.role === '') {
      return fail(`${at}.role`, 'role: Field required (a non-empty string)');
    }
    if (typeof m.content !== 'string' && !Array.isArray(m.content)) {
      return fail(`${at}.content`, 'content must be a string or an array of content blocks');
    }
  }
  if (system !== undefined && typeof system !== 'string' && !Array.isArray(system)) {
    return fail('system', 'system must be a string or an array of text blocks');
  }
  if (stream !== undefined && typeof stream !== 'boolean') {
    return fail('stream', 'stream must be a boolean');
  }

  return { kind: 'ok', value: { model, max_tokens, stream: stream === true } };
}

/**
 * An error body in the Anthropic dialect — what a client of this route can
 * parse. `type` is one of the API's own error types; the enclave uses
 * `invalid_request_error`, `authentication_error`, `permission_error`,
 * `rate_limit_error`, `api_error` and `overloaded_error`. Never content.
 */
export function anthropicErrorBody(type, message) {
  return { type: 'error', error: { type, message } };
}

/** The Anthropic error type an HTTP status maps to, for a status we answer ourselves. */
export function anthropicErrorTypeFor(status) {
  if (status === 400) return 'invalid_request_error';
  if (status === 401) return 'authentication_error';
  if (status === 402 || status === 403) return 'permission_error';
  if (status === 404) return 'not_found_error';
  if (status === 413) return 'request_too_large';
  if (status === 429) return 'rate_limit_error';
  if (status === 529) return 'overloaded_error';
  return 'api_error';
}

/**
 * One Anthropic content block as the chat-completions part `measureInput`
 * already knows how to strip and count. Text-bearing blocks keep their text
 * (tool_use input and tool_result content are billed input too); media is
 * reduced to the shape that tallies as an image or a file, never as text.
 * Unknown block types pass through and are counted as text: over-counting
 * is the safe direction for a spend check. A block built from nested blocks
 * returns an ARRAY of parts (see toChatParts).
 */
function toChatPart(block, depth = 0) {
  if (typeof block === 'string') return { type: 'text', text: block };
  if (!isPlainRecord(block)) return block;
  switch (block.type) {
    case 'text':
    case 'thinking':
    case 'redacted_thinking':
      return block;
    case 'image':
      // base64 or URL source; either way one image part, no bytes counted.
      return { type: 'image' };
    case 'document': {
      // Four source shapes (Anthropic Messages): base64 bytes, plain text,
      // nested content blocks, and a URL the provider fetches. Only the first
      // used to be carried; the other three were projected onto a file part
      // with no bytes and measured at ~0 tokens while the verbatim body was
      // billed in full upstream (Oct 17-19 security reports, saputraginan222:
      // an 8,045-token text document measured as 26). Text and content count
      // as the text they are; a URL is a `url_parts` reference measureInput
      // flags for hp. The title is prompt text too; it rides as the filename
      // the file branch keeps.
      const src = block.source;
      const filename = typeof block.title === 'string' ? block.title : undefined;
      if (src?.type === 'text') {
        return { type: 'text', text: typeof src.data === 'string' ? src.data : JSON.stringify(src.data ?? null) };
      }
      if (src?.type === 'content') {
        const content = src.content;
        if (typeof content === 'string') return { type: 'text', text: content };
        // Nested blocks stay PARTS, not a JSON string: a document assembled
        // from content blocks may carry images, and an image serialized into
        // text would never reach `image_parts` (CodeRabbit on #326).
        if (Array.isArray(content) && depth < 2) {
          return content.flatMap((b) => toChatParts(b, depth + 1));
        }
        return { type: 'text', text: JSON.stringify(content ?? null) };
      }
      if (src?.type === 'url') {
        return { type: 'file', file: { filename, file_url: typeof src.url === 'string' ? src.url : String(src.url ?? '') } };
      }
      const data = src?.type === 'base64' ? src.data : undefined;
      return { type: 'file', file: { filename, file_data: data } };
    }
    case 'tool_use':
      return { type: 'text', text: JSON.stringify({ tool_use: block.name, input: block.input ?? null }) };
    case 'tool_result': {
      const content = block.content;
      if (typeof content === 'string') return { type: 'text', text: content };
      // Same as the document case above: a tool result's image blocks must
      // reach the image tally, so nested blocks are flattened into parts.
      if (Array.isArray(content) && depth < 2) {
        return content.flatMap((b) => toChatParts(b, depth + 1));
      }
      return { type: 'tool_result' };
    }
    default:
      return block;
  }
}

/**
 * `toChatPart`, always as a list: a block that projects onto several parts
 * (a document or tool result built from nested blocks) spreads into its
 * siblings, so every nested image and text block is measured as itself.
 */
function toChatParts(block, depth = 0) {
  const part = toChatPart(block, depth);
  return Array.isArray(part) ? part : [part];
}

/**
 * The Anthropic body projected onto the chat shape `measureInput` walks:
 * `system` (string or text blocks) becomes a leading system message, each
 * message's blocks become parts, and `tools` ride along (billed input the
 * chat measure already includes). Pure; exported for tests.
 */
export function toChatShapeForMeasure(body) {
  const messages = [];
  if (typeof body?.system === 'string') {
    messages.push({ role: 'system', content: body.system });
  } else if (Array.isArray(body?.system)) {
    messages.push({ role: 'system', content: body.system.flatMap((b) => toChatParts(b)) });
  }
  for (const m of Array.isArray(body?.messages) ? body.messages : []) {
    if (!isPlainRecord(m)) continue;
    messages.push({
      role: m.role,
      content: Array.isArray(m.content) ? m.content.flatMap((b) => toChatParts(b)) : m.content,
    });
  }
  const out = { messages };
  if (Array.isArray(body?.tools) && body.tools.length) out.tools = body.tools;
  return out;
}

/**
 * The input measure hp bounds spend with: the same fields the chat path sends
 * (`input_tokens_o200k`, `message_count`, `image_parts`, `file_bytes`,
 * `audio_bytes`, `url_parts`), over the Anthropic body, plus the endpoint and a byte
 * fallback. `message_count` counts the caller's messages, not the synthetic
 * system message. Never throws.
 */
export async function measureMessagesInput(body) {
  const serialized = JSON.stringify({ system: body?.system, messages: body?.messages, tools: body?.tools });
  const measured = await measureInput(toChatShapeForMeasure(body));
  return {
    endpoint: MESSAGES_ENDPOINT,
    input_bytes: Buffer.byteLength(serialized),
    ...measured,
    message_count: Array.isArray(body?.messages) ? body.messages.length : 0,
  };
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);
const optNum = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined);

/**
 * Usage out of one Messages `usage` object, in the settle's vocabulary.
 * Anthropic's counts are ADDITIVE: `input_tokens` excludes both cache
 * buckets (hp's settle folds them under that convention, cache-write premium
 * included). Via OpenRouter the object also carries `cost` and, for BYOK,
 * `cost_details.upstream_inference_cost`, the same keys cost.mjs reads.
 */
function usageFields(usage) {
  if (!isPlainRecord(usage)) return {};
  const out = {};
  if (usage.input_tokens !== undefined) out.inputTokens = num(usage.input_tokens);
  if (usage.output_tokens !== undefined) out.outputTokens = num(usage.output_tokens);
  const read = optNum(usage.cache_read_input_tokens);
  const write = optNum(usage.cache_creation_input_tokens);
  if (read !== undefined) out.cacheReadTokens = read;
  if (write !== undefined) out.cacheWriteTokens = write;
  // BYOK bills the provider's inference cost only when the frame carries
  // one; a BYOK-flagged frame without it is billed from OpenRouter's `cost`,
  // Exa charge included, and must not report itself as BYOK (horse-power
  // #1088 would add the fee on a cost that already carries it).
  const byokCost = usage.is_byok === true && isPlainRecord(usage.cost_details) && usage.cost_details.upstream_inference_cost != null;
  const cost = byokCost ? num(usage.cost_details.upstream_inference_cost) : optNum(usage.total_cost ?? usage.cost);
  if (cost !== undefined) {
    out.totalCost = cost;
    out.costReported = true;
    // A boolean once a cost has been read: `true` when it is the BYOK
    // provider's inference cost (OpenRouter's own charges, the Exa web-search
    // fee among them, excluded), `false` when it is OpenRouter's `cost`, the
    // branch that supplied `totalCost`. The settle reports it as `is_byok`.
    out.isByok = byokCost;
  }
  return out;
}

const EMPTY_USAGE = Object.freeze({
  inputTokens: 0,
  outputTokens: 0,
  totalCost: 0,
  costReported: false,
  generationId: '',
  servedModel: undefined,
  stopReason: undefined,
  provider: undefined,
});

/**
 * OpenRouter's serving sub-provider ("Fireworks", "DeepInfra", …) off one
 * Messages record. OpenRouter puts it on the message object (JSON body,
 * message_start.message) and may also repeat it top-level on stream events;
 * the same name gate as the chat path (cost.mjs) applies. undefined when
 * absent or not a plausible name: it is display-only on the settle.
 */
const providerOf = (record) => (isPlainRecord(record) ? providerName(record.provider) : undefined);

/**
 * Usage from a NON-streaming Messages answer: one JSON body carrying `model`,
 * `id`, `stop_reason` and a complete `usage`. The settle is built from this.
 */
export function messagesUsage(body) {
  if (!isPlainRecord(body)) return { ...EMPTY_USAGE };
  return {
    ...EMPTY_USAGE,
    ...usageFields(body.usage),
    generationId: typeof body.id === 'string' && body.id.startsWith('gen-') ? body.id : '',
    servedModel: typeof body.model === 'string' ? body.model : undefined,
    stopReason: typeof body.stop_reason === 'string' ? body.stop_reason : undefined,
    provider: providerOf(body),
  };
}

/**
 * Usage from a STREAMED Messages answer, fed one SSE line at a time while the
 * frames go through to the client untouched.
 *
 * Event grammar: message_start (model, id, the only complete input-side
 * usage) → content_block_* → message_delta (stop_reason + cumulative
 * output_tokens; via OpenRouter also the cost) → message_stop. `ping` may
 * appear anywhere. An `error` event, or a stream that ends before
 * message_stop, is a failed generation.
 *
 * Merging is field-wise: a later event silent on a field never erases what
 * an earlier one reported, so a message_delta without input_tokens does not
 * zero what message_start said (the bug hp's parser documents).
 */
export class MessagesUsageExtractor {
  constructor() {
    this.result = { ...EMPTY_USAGE };
    /** 'message_stop' | 'error' | null — how the stream ended, if it has. */
    this.terminal = null;
    this.errorMessage = undefined;
    this.sawStart = false;
  }

  /** The last `data:` payload on a line, parsed; null for anything else. */
  static parseLine(line) {
    const s = typeof line === 'string' ? line : String(line ?? '');
    if (!s.startsWith('data:')) return null;
    const json = s.slice(5).trim();
    if (!json || json === '[DONE]') return null;
    try {
      const v = JSON.parse(json);
      return isPlainRecord(v) ? v : null;
    } catch {
      return null;
    }
  }

  feed(line) {
    if (this.terminal) return;
    const event = MessagesUsageExtractor.parseLine(line);
    if (!event) return;
    switch (event.type) {
      case 'message_start': {
        const message = isPlainRecord(event.message) ? event.message : {};
        this.sawStart = true;
        if (typeof message.model === 'string') this.result.servedModel = message.model;
        if (typeof message.id === 'string' && message.id.startsWith('gen-')) this.result.generationId = message.id;
        this.#noteProvider(providerOf(message) ?? providerOf(event));
        // message_start's output_tokens is a placeholder (Anthropic sends 1);
        // the real count arrives on message_delta. Keeping it would make a
        // stream cut before message_delta look priced by the upstream.
        const { outputTokens: _placeholder, ...fields } = usageFields(message.usage);
        Object.assign(this.result, fields);
        return;
      }
      case 'message_delta': {
        if (typeof event.delta?.stop_reason === 'string') this.result.stopReason = event.delta.stop_reason;
        Object.assign(this.result, usageFields(event.usage));
        this.#noteProvider(providerOf(event));
        return;
      }
      case 'message_stop':
        this.#noteProvider(providerOf(event));
        this.terminal = 'message_stop';
        return;
      case 'error': {
        this.terminal = 'error';
        const detail = event.error?.message || event.error?.type;
        this.errorMessage = typeof detail === 'string' ? detail.slice(0, 300) : 'stream error';
        return;
      }
      default:
        return;
    }
  }

  /** Field-wise like the usage: an event silent on the provider keeps the earlier one. */
  #noteProvider(provider) {
    if (provider !== undefined) this.result.provider = provider;
  }

  /** Whether the generation completed: message_stop seen, no error. */
  get completed() {
    return this.terminal === 'message_stop';
  }
}

/**
 * The in-band frame a Messages client reads as "the generation died" once the
 * 200 and the first bytes are on the wire (hp #894, Anthropic dialect). The
 * message is a fixed, content-free string: never the upstream's own text.
 */
export function messagesStreamErrorFrame(message = 'upstream error') {
  return `event: error\ndata: ${JSON.stringify(anthropicErrorBody('api_error', message))}\n\n`;
}

/**
 * Anthropic's `count_tokens` rejects any field outside this set, and Claude
 * Code sends plenty of them (`max_tokens`, `metadata`, `stream`, ...).
 * Mirrored from horse-power's COUNT_TOKENS_FIELDS: every count-bearing field
 * is forwarded, because a count without `tools` is wrong by two orders of
 * magnitude, which is worse than an error.
 */
export const COUNT_TOKENS_FIELDS = Object.freeze([
  'messages',
  'system',
  'tools',
  'tool_choice',
  'thinking',
  'mcp_servers',
]);

/** The count_tokens body for Anthropic, with the model pinned to the first-party id. */
export function projectCountTokensBody(body, upstreamModelId) {
  const out = { model: upstreamModelId };
  if (!isPlainRecord(body)) return out;
  for (const field of COUNT_TOKENS_FIELDS) {
    if (body[field] !== undefined) out[field] = body[field];
  }
  return out;
}

/** Delivered text the counter keeps before it stops counting precisely. */
export const MAX_COUNTED_DELTA_CHARS = 2_000_000;

/**
 * What actually went out, for the settle when the usage never came: the
 * client hung up and the upstream was cancelled before message_delta, or the
 * stream died. Counts the text of `content_block_delta` events (text,
 * thinking, tool-input JSON) with o200k; the Messages twin of
 * outputCount.mjs, bounded the same way.
 */
export class MessagesOutputCounter {
  constructor() {
    this.text = '';
    this.chars = 0;
    this.overflowChars = 0;
  }

  feed(line) {
    const event = MessagesUsageExtractor.parseLine(line);
    if (!event || event.type !== 'content_block_delta') return;
    const d = event.delta;
    const piece = typeof d?.text === 'string' ? d.text
      : typeof d?.partial_json === 'string' ? d.partial_json
        : typeof d?.thinking === 'string' ? d.thinking
          : '';
    if (!piece) return;
    this.chars += piece.length;
    if (this.text.length + piece.length <= MAX_COUNTED_DELTA_CHARS) this.text += piece;
    else this.overflowChars += piece.length;
  }

  /** `{ chars, tokens }`; tokens are counted in slices, overflow at 4 chars/token. */
  async finish() {
    let tokens = 0;
    const countTokens = await loadTokenizer();
    if (countTokens && this.text) {
      const opts = { disallowedSpecial: new Set() };
      for (let i = 0; i < this.text.length; i += TOKENIZE_SLICE_CHARS) {
        tokens += countTokens(this.text.slice(i, i + TOKENIZE_SLICE_CHARS), opts);
      }
    }
    tokens += Math.ceil(this.overflowChars / 4);
    return { chars: this.chars, tokens };
  }
}

/** Whether the body asks for Anthropic's web search server tool (billed as online). */
export function messagesHasWebSearch(body) {
  const tools = Array.isArray(body?.tools) ? body.tools : [];
  return tools.some((t) => isPlainRecord(t) && typeof t.type === 'string' && t.type.startsWith('web_search'));
}

/**
 * hp's `:online` directive (horse-power #1055) on the Messages dialect:
 * Anthropic's dated web search tool. NOT the `web` plugin: OpenRouter's
 * Anthropic-compat endpoint silently ignores it (horse-power #891), and the
 * dated tool is the only form it runs. Mirrors hp's carryWebPluginAsServerTool,
 * including leaving a body that already declares a search tool as it is.
 * `max_uses` is left to the upstream default, as hp does.
 *
 * One rule for every model, deliberately simpler than hp's cleartext path,
 * which first runs the chat swaps and so hands Claude models
 * `openrouter:web_search` instead. The dated tool searches on Claude too
 * (measured 2026-10-12 on claude-fable-latest and claude-sonnet-5:
 * server_tool_use + web_search_tool_result), and it is the only form that
 * works on every model, so this relay needs no model table to choose.
 */
export function applyMessagesWebSearch(body) {
  const tools = Array.isArray(body.tools) ? body.tools : [];
  if (tools.some((t) => isPlainRecord(t) && t.type === 'openrouter:web_search') || messagesHasWebSearch(body)) {
    return;
  }
  body.tools = [...tools, { type: 'web_search_20250305', name: 'web_search' }];
}

/**
 * The free-model strip in the Messages shape (Oct 17-19 security reports:
 * martan, hel, Raju Arling Toni). The chat path has had applyFreeModelStrip
 * since issue #6; this relay forwarded the body verbatim, so a free credential
 * could send Anthropic's `web_search_*` server tool or OpenRouter's `web`
 * plugin and the search ran, billed to PPQ, on a settle marked is_free_model.
 * Drops `plugins` and every web search tool; a `tool_choice` that named the
 * removed tool goes with it, or the upstream 400s the whole request.
 */
export function applyMessagesFreeModelStrip(body) {
  if (!isPlainRecord(body)) return;
  if ('plugins' in body) delete body.plugins;
  if (!Array.isArray(body.tools)) return;
  const isWebSearch = (t) =>
    isPlainRecord(t) && typeof t.type === 'string' && (t.type.startsWith('web_search') || t.type === 'openrouter:web_search');
  const removed = body.tools.filter(isWebSearch);
  if (removed.length === 0) return;
  body.tools = body.tools.filter((t) => !isWebSearch(t));
  const choice = body.tool_choice;
  const choiceTargetsRemoved =
    isPlainRecord(choice) && choice.type === 'tool' && removed.some((t) => t.name === choice.name);
  if (body.tools.length === 0) {
    delete body.tools;
    delete body.tool_choice;
  } else if (choiceTargetsRemoved) {
    delete body.tool_choice;
  }
}

/**
 * hp's strip_tools directive (the model's catalog row has no tool support) in
 * the Messages shape: the chat path's applyToolStrip, same guard (only a
 * non-empty tools array is touched).
 */
export function applyMessagesToolStrip(body) {
  if (!isPlainRecord(body)) return;
  if (Array.isArray(body.tools) && body.tools.length > 0) {
    delete body.tools;
    delete body.tool_choice;
  }
}

/**
 * The first-party Anthropic model id a count_tokens call is made with.
 *
 * Preferred: the wire model of hp's Anthropic direct candidate, which is the
 * dated id hp itself serves the model under. When hp offers no such
 * candidate (direct providers off, or the row absent, as on dev), the id is
 * derived from the resolved slug: `anthropic/claude-sonnet-4.6` →
 * `claude-sonnet-4-6`, the undated alias Anthropic publishes for each
 * current model; an id the caller already gave in Anthropic's own form
 * (`claude-sonnet-4-6`, no vendor prefix) is used as is. Anything that is
 * not a Claude model has no first-party id and the count is refused.
 */
export function anthropicFirstPartyId(resolvedModel, upstreams) {
  const direct = (Array.isArray(upstreams) ? upstreams : []).find(
    (u) => isPlainRecord(u) && u.api_style === 'anthropic' && typeof u.upstream_model === 'string' && u.upstream_model,
  );
  if (direct) return direct.upstream_model;
  const slug = typeof resolvedModel === 'string' ? resolvedModel.trim() : '';
  const bare = slug.startsWith('anthropic/') ? slug.slice('anthropic/'.length) : slug.includes('/') ? '' : slug;
  // A `:suffix` (OpenRouter routing preference) is not part of the model.
  const base = bare.split(':')[0];
  if (!/^claude[a-z0-9.-]*$/i.test(base)) return null;
  return base.replace(/\./g, '-');
}

/**
 * Keep `thinking.budget_tokens` under `max_tokens` once the cap has lowered
 * the latter: the API refuses a budget at or above max_tokens with a 400,
 * and Claude Code sends extended-thinking turns with the two close together,
 * so without this the cap turned a shorter answer into an error for exactly
 * the low-balance users it exists for. Under the API's minimum budget the
 * turn runs without thinking rather than not at all.
 */
export const THINKING_MIN_BUDGET_TOKENS = 1024;
export function clampThinkingBudget(body) {
  const t = body?.thinking;
  if (!t || typeof t !== 'object' || t.type !== 'enabled' || !Number.isInteger(t.budget_tokens)) return;
  if (t.budget_tokens < body.max_tokens) return;
  const budget = body.max_tokens - 1;
  if (budget >= THINKING_MIN_BUDGET_TOKENS) body.thinking = { ...t, budget_tokens: budget };
  else body.thinking = { type: 'disabled' };
}

/** hp's output cap on the field this API requires anyway, with the thinking budget kept under it. */
export function applyMessagesCap(body, cap) {
  body.max_tokens = Math.min(body.max_tokens, cap);
  clampThinkingBudget(body);
}

/**
 * What server.mjs's dialect relay needs to serve this dialect (#275, #280):
 * every dialect-specific decision in one object, so the relay itself holds
 * only what needs the tunnels, EHBP, hp and the settle queue.
 */
export const MESSAGES_DIALECT = Object.freeze({
  name: 'messages',
  path: MESSAGES_PATH,
  endpoint: MESSAGES_ENDPOINT,
  upstreamPath: MESSAGES_UPSTREAM_PATH,
  costSource: MESSAGES_COST_SOURCE,
  maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
  maxResponseBytes: MAX_RESPONSE_BYTES,
  // The dialect's own version/beta headers ride through: they select API
  // behaviour, not identity, and OpenRouter forwards them to the provider.
  forwardHeaders: ['anthropic-version', 'anthropic-beta'],
  validate: validateMessagesRequest,
  measure: measureMessagesInput,
  requestedMaxTokens: (body) => body.max_tokens,
  applyCap: applyMessagesCap,
  // The Messages API has no per-end-user identity field.
  applyIdentity: () => {},
  UsageExtractor: MessagesUsageExtractor,
  OutputCounter: MessagesOutputCounter,
  usageOf: messagesUsage,
  errorBody: (status, message) => anthropicErrorBody(anthropicErrorTypeFor(status), message),
  streamErrorFrame: messagesStreamErrorFrame,
  capHit: (extractor) => extractor.result.stopReason === 'max_tokens',
  hasWebSearch: messagesHasWebSearch,
  applyWebSearch: applyMessagesWebSearch,
  applyFreeModelStrip: applyMessagesFreeModelStrip,
  applyToolStrip: applyMessagesToolStrip,
  usageMissingCode: ERROR_CODES.MESSAGES_USAGE_MISSING,
  // hp #1139 phase 2: providers that serve THIS dialect natively, so an
  // /authorize candidate for one of them is tried before OpenRouter, through
  // the provider's own tunnel and key, on `directPath` at the candidate's
  // host. Fireworks: a real Anthropic grammar on /v1/messages (probed
  // 2026-10-26 on kimi-k3), prefix caching included, with its usage split
  // the other way round from Anthropic's (zeros on message_start, the full
  // counts on message_delta) — which the field-wise merge above already
  // handles. Fireworks on Foundry answers `api_not_supported` on its
  // /anthropic/v1/messages for the Fireworks deployments (probed the same
  // day), so it stays on the chat dialect only. A candidate the gate finds
  // ineligible, or whose attempt fails, falls through to OpenRouter as
  // before; the Responses dialect declares none.
  directProviders: new Set(['fireworks']),
  directPath: '/v1/messages',
});
