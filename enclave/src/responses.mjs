/**
 * `/v1/responses` — the OpenAI Responses API, served IN the enclave (#280),
 * the last chat surface that still transited the enclave to horse-power in
 * plaintext.
 *
 * As with the Messages dialect (messages.mjs, #275): horse-power serves this
 * route on the enclave-bypass host by forwarding the body AS-IS to
 * OpenRouter's `/api/v1/responses`, and the enclave does the same. This
 * module holds the pure parts the dialect relay in server.mjs needs; the
 * Responses wire grammar is already known here — bedrock.mjs speaks it to
 * bedrock-mantle as an UPSTREAM dialect and parses its SSE back into chat
 * chunks. This module parses the same events for a client that speaks the
 * dialect itself; only the numbers are read.
 *
 * Everything returned to hp is a count or a closed value: no content leaves.
 */
import { createHmac } from 'node:crypto';
import { loadTokenizer, measureInput, TOKENIZE_SLICE_CHARS } from './inputEstimate.mjs';
import { ERROR_CODES } from './errorReport.mjs';

/** Where the client posts (both spellings hp registers), and where OpenRouter serves it. */
export const RESPONSES_PATHS = Object.freeze(['/v1/responses', '/responses']);
export const RESPONSES_UPSTREAM_PATH = '/api/v1/responses';
/** What `/enclave/authorize` learns about the request. */
export const RESPONSES_ENDPOINT = 'responses';
/** `cost_source` on the settle: OpenRouter's usage on `response.completed` or the body. */
export const RESPONSES_COST_SOURCE = 'responses-usage';

/** Same bounds as the Messages dialect: one sealed request, one JSON answer. */
export const MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024;
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

const isPlainRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Validate a Responses body — only as far as the relay needs. The body is
 * forwarded verbatim; OpenRouter and the provider keep their own checks.
 * Pinned here: the model it authorizes, the `input` it measures, the
 * optional `max_output_tokens` it caps and the `stream` that decides how
 * the answer is metered. `input` may be a string or a list of items.
 */
export function validateResponsesRequest(body) {
  const fail = (field, message) => ({ kind: 'invalid', error: { field, message } });

  if (!isPlainRecord(body)) return fail('body', 'Request body must be a JSON object');
  const { model, input, instructions, max_output_tokens, stream } = body;

  if (typeof model !== 'string' || model.trim() === '') {
    return fail('model', 'Missing required field: model');
  }
  if (typeof input !== 'string' && !Array.isArray(input)) {
    return fail('input', 'input: Field required (a string or an array of input items)');
  }
  if (Array.isArray(input)) {
    for (let i = 0; i < input.length; i++) {
      if (!isPlainRecord(input[i])) return fail(`input.${i}`, 'Each input item must be an object');
    }
  }
  if (instructions !== undefined && instructions !== null && typeof instructions !== 'string') {
    return fail('instructions', 'instructions must be a string');
  }
  if (max_output_tokens !== undefined && max_output_tokens !== null && (!Number.isInteger(max_output_tokens) || max_output_tokens < 1)) {
    return fail('max_output_tokens', 'max_output_tokens must be a positive integer');
  }
  if (stream !== undefined && typeof stream !== 'boolean') {
    return fail('stream', 'stream must be a boolean');
  }
  return { kind: 'ok', value: { model, max_output_tokens: max_output_tokens ?? undefined, stream: stream === true } };
}

/**
 * An error body in the OpenAI dialect, what a Responses client parses:
 * `{ error: { message, type, code } }`. `type` follows OpenAI's vocabulary
 * for the statuses the enclave answers itself. Never content.
 */
export function openaiErrorBody(status, message) {
  const type =
    status === 400 ? 'invalid_request_error'
      : status === 401 ? 'authentication_error'
        : status === 402 || status === 403 ? 'permission_error'
          : status === 404 ? 'not_found_error'
            : status === 429 ? 'rate_limit_error'
              : 'server_error';
  return { error: { message, type, code: status } };
}

/**
 * The in-band frame a Responses client reads as "the generation died" once
 * the 200 and the first bytes are on the wire (hp #894): a named `error`
 * event with a typed payload, never a chat-shaped `data: {"error":…}`.
 */
export function responsesStreamErrorFrame(message = 'upstream error') {
  return `event: error\ndata: ${JSON.stringify({ type: 'error', code: 'upstream_error', message })}\n\n`;
}

/**
 * One Responses content part as the chat-completions part `measureInput`
 * strips and counts. Text keeps its text; an image tallies as an image
 * part; a file as its base64 bytes; unknown parts pass through and count as
 * text, the safe direction for a spend check.
 */
function toChatPart(part) {
  if (typeof part === 'string') return { type: 'text', text: part };
  if (!isPlainRecord(part)) return part;
  switch (part.type) {
    case 'input_text':
    case 'output_text':
    case 'text':
      return { type: 'text', text: typeof part.text === 'string' ? part.text : '' };
    case 'input_image':
    case 'image_url':
      return { type: 'image' };
    case 'input_file':
    case 'file':
      return { type: 'file', file: { file_data: typeof part.file_data === 'string' ? part.file_data : undefined } };
    default:
      return part;
  }
}

/** One input item as a chat message (or null for an item that carries no billable text). */
function toChatMessage(item) {
  if (typeof item === 'string') return { role: 'user', content: item };
  if (!isPlainRecord(item)) return null;
  switch (item.type) {
    case undefined:
    case 'message': {
      const role = typeof item.role === 'string' ? item.role : 'user';
      const content = Array.isArray(item.content) ? item.content.map(toChatPart) : item.content;
      return { role, content };
    }
    case 'function_call':
      return { role: 'assistant', content: JSON.stringify({ call: item.name, arguments: item.arguments ?? null }) };
    case 'function_call_output':
      return { role: 'tool', content: typeof item.output === 'string' ? item.output : JSON.stringify(item.output ?? null) };
    case 'reasoning':
      return { role: 'assistant', content: JSON.stringify(item.summary ?? item.content ?? null) };
    default:
      // An item type this build does not know: counted whole as text.
      return { role: 'user', content: JSON.stringify(item) };
  }
}

/**
 * The Responses body projected onto the chat shape `measureInput` walks:
 * `instructions` becomes a leading system message, a string `input` one
 * user message, an item list one message per item; `tools` ride along.
 * Pure; exported for tests.
 */
export function toChatShapeForMeasure(body) {
  const messages = [];
  if (typeof body?.instructions === 'string' && body.instructions) {
    messages.push({ role: 'system', content: body.instructions });
  }
  const input = body?.input;
  if (typeof input === 'string') {
    messages.push({ role: 'user', content: input });
  } else if (Array.isArray(input)) {
    for (const item of input) {
      const m = toChatMessage(item);
      if (m) messages.push(m);
    }
  }
  const out = { messages };
  if (Array.isArray(body?.tools) && body.tools.length) out.tools = body.tools;
  return out;
}

/**
 * The input measure hp bounds spend with (the same fields the chat path
 * sends), over the Responses body, plus the endpoint and a byte fallback.
 * `message_count` is the number of input items (1 for a string). Never
 * throws.
 */
export async function measureResponsesInput(body) {
  const serialized = JSON.stringify({ instructions: body?.instructions, input: body?.input, tools: body?.tools });
  const measured = await measureInput(toChatShapeForMeasure(body));
  const input = body?.input;
  return {
    endpoint: RESPONSES_ENDPOINT,
    input_bytes: Buffer.byteLength(serialized),
    ...measured,
    message_count: typeof input === 'string' ? 1 : Array.isArray(input) ? input.length : 0,
  };
}

/** hp's output cap on `max_output_tokens`: set when the caller sent none, clamped when they did. */
export function applyResponsesCap(body, cap) {
  const requested = body.max_output_tokens;
  body.max_output_tokens = Number.isInteger(requested) && requested > 0 ? Math.min(requested, cap) : cap;
}

// ── OpenAI safety identifier (issue #657), the Responses spelling ──────────
// Mirrors routing.mjs applySafetyIdentifier (chat: `user`) and horse-power
// chatPayload.ts applySafetyIdentifier (`/responses`: `safety_identifier`;
// `user` is deprecated there and rejected by some upstream versions). Ours
// overrides any caller-supplied value for OpenAI models; other models are
// left untouched. No-op without the secret.
function isOpenAiFamilyModel(model) {
  return typeof model === 'string' && model.startsWith('openai/') && !model.startsWith('openai/gpt-oss');
}
export function applyResponsesSafetyIdentifier(body, creditId, secret) {
  if (!isOpenAiFamilyModel(body?.model)) return;
  if (typeof creditId !== 'string' || !creditId || !secret) return;
  body.safety_identifier = createHmac('sha256', secret).update(creditId).digest('hex');
  delete body.user;
}

/** Whether the body asks for OpenAI's web search tool (billed as online). */
export function responsesHasWebSearch(body) {
  const tools = Array.isArray(body?.tools) ? body.tools : [];
  return tools.some((t) => isPlainRecord(t) && typeof t.type === 'string' && t.type.startsWith('web_search'));
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);
const optNum = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined);

/**
 * Usage out of one Responses `usage` object, in the settle's vocabulary.
 * `input_tokens` INCLUDES the cached tokens (the subset convention
 * cost.mjs and hp's settle already handle for the Bedrock direct path);
 * reasoning tokens ride under `output_tokens_details`. Via OpenRouter the
 * object also carries `cost` and, for BYOK, `cost_details`.
 */
function usageFields(usage) {
  if (!isPlainRecord(usage)) return {};
  const out = {};
  if (usage.input_tokens !== undefined) out.inputTokens = num(usage.input_tokens);
  if (usage.output_tokens !== undefined) out.outputTokens = num(usage.output_tokens);
  const cached = optNum(usage.input_tokens_details?.cached_tokens);
  if (cached !== undefined) out.cacheReadTokens = cached;
  const write = optNum(usage.input_tokens_details?.cache_write_tokens);
  if (write !== undefined) out.cacheWriteTokens = write;
  const reasoning = optNum(usage.output_tokens_details?.reasoning_tokens);
  if (reasoning !== undefined) out.reasoningTokens = reasoning;
  const byok = usage.is_byok === true;
  const cost = byok && isPlainRecord(usage.cost_details) && usage.cost_details.upstream_inference_cost != null
    ? num(usage.cost_details.upstream_inference_cost)
    : optNum(usage.total_cost ?? usage.cost);
  if (cost !== undefined) {
    out.totalCost = cost;
    out.costReported = true;
    if (byok) out.isByok = true;
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
});

/** The facts a `response` object carries, whole (JSON) or on a terminal event. */
function responseFields(response) {
  if (!isPlainRecord(response)) return {};
  const out = usageFields(response.usage);
  if (typeof response.id === 'string' && response.id.startsWith('gen-')) out.generationId = response.id;
  if (typeof response.model === 'string') out.servedModel = response.model;
  if (response.status === 'incomplete') {
    out.stopReason = typeof response.incomplete_details?.reason === 'string' ? response.incomplete_details.reason : 'incomplete';
  } else if (response.status === 'completed') {
    out.stopReason = 'completed';
  }
  return out;
}

/** Usage from a NON-streaming Responses answer: one JSON `response` object. */
export function responsesUsage(body) {
  if (!isPlainRecord(body)) return { ...EMPTY_USAGE };
  return { ...EMPTY_USAGE, ...responseFields(body) };
}

/**
 * Usage from a STREAMED Responses answer, fed one SSE line at a time while
 * the frames go through to the client untouched.
 *
 * Event grammar: response.created (model, id) → response.output_item.* /
 * response.output_text.delta / response.function_call_arguments.* /
 * reasoning deltas → response.completed or response.incomplete (the whole
 * `response` with its usage; `incomplete` is a TERMINATED generation with
 * a reason, e.g. max_output_tokens) → nothing after. response.failed and a
 * bare `{"type":"error"}` are failed generations. Merging is field-wise.
 */
export class ResponsesUsageExtractor {
  constructor() {
    this.result = { ...EMPTY_USAGE };
    /** 'completed' | 'incomplete' | 'error' | null — how the stream ended, if it has. */
    this.terminal = null;
    this.errorMessage = undefined;
  }

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
    const event = ResponsesUsageExtractor.parseLine(line);
    if (!event) return;
    switch (event.type) {
      case 'response.created':
      case 'response.in_progress':
        Object.assign(this.result, responseFields(event.response));
        return;
      case 'response.completed':
        Object.assign(this.result, responseFields(event.response));
        this.terminal = 'completed';
        return;
      case 'response.incomplete':
        Object.assign(this.result, responseFields(event.response));
        this.terminal = 'incomplete';
        return;
      case 'response.failed': {
        Object.assign(this.result, responseFields(event.response));
        this.terminal = 'error';
        const detail = event.response?.error?.message || event.response?.error?.code;
        this.errorMessage = typeof detail === 'string' ? detail.slice(0, 300) : 'response failed';
        return;
      }
      case 'error': {
        this.terminal = 'error';
        const detail = event.message || event.code;
        this.errorMessage = typeof detail === 'string' ? detail.slice(0, 300) : 'stream error';
        return;
      }
      default:
        return;
    }
  }

  /** Whether the generation terminated normally: completed, or incomplete with a reason. */
  get completed() {
    return this.terminal === 'completed' || this.terminal === 'incomplete';
  }
}

/** Delivered text the counter keeps before it stops counting precisely. */
export const MAX_COUNTED_DELTA_CHARS = 2_000_000;

/**
 * What actually went out, for the settle when the usage never came: the
 * text of the delta events (output text, function-call arguments, reasoning
 * text), counted with o200k. The Responses twin of outputCount.mjs.
 */
export class ResponsesOutputCounter {
  constructor() {
    this.text = '';
    this.chars = 0;
    this.overflowChars = 0;
  }

  feed(line) {
    const event = ResponsesUsageExtractor.parseLine(line);
    if (!event || typeof event.type !== 'string') return;
    if (!/^response\.(output_text|function_call_arguments|reasoning_summary_text|reasoning_text|refusal)\.delta$/.test(event.type)) return;
    const piece = typeof event.delta === 'string' ? event.delta : '';
    if (!piece) return;
    this.chars += piece.length;
    if (this.text.length + piece.length <= MAX_COUNTED_DELTA_CHARS) this.text += piece;
    else this.overflowChars += piece.length;
  }

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

/** What server.mjs's dialect relay needs to serve this dialect (#280). */
export const RESPONSES_DIALECT = Object.freeze({
  name: 'responses',
  path: '/v1/responses',
  endpoint: RESPONSES_ENDPOINT,
  upstreamPath: RESPONSES_UPSTREAM_PATH,
  costSource: RESPONSES_COST_SOURCE,
  maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
  maxResponseBytes: MAX_RESPONSE_BYTES,
  forwardHeaders: [],
  validate: validateResponsesRequest,
  measure: measureResponsesInput,
  requestedMaxTokens: (body) => body.max_output_tokens ?? undefined,
  applyCap: applyResponsesCap,
  applyIdentity: applyResponsesSafetyIdentifier,
  UsageExtractor: ResponsesUsageExtractor,
  OutputCounter: ResponsesOutputCounter,
  usageOf: responsesUsage,
  errorBody: openaiErrorBody,
  streamErrorFrame: responsesStreamErrorFrame,
  capHit: (extractor) => extractor.result.stopReason === 'max_output_tokens',
  hasWebSearch: responsesHasWebSearch,
  usageMissingCode: ERROR_CODES.RESPONSES_USAGE_MISSING,
});
