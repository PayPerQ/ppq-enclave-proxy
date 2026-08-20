/**
 * Anthropic direct upstream — the `api_style: 'anthropic'` adapter.
 *
 * The client speaks OpenAI /chat/completions; api.anthropic.com speaks the
 * Messages API (/v1/messages, x-api-key auth, its own SSE event grammar).
 * This module owns the two-way translation:
 *
 *   request : projected chat body ──toMessagesRequest──▶ /v1/messages JSON
 *   response: Anthropic SSE events ──MessagesToChatSse──▶ chat-chunk SSE
 *
 * Ordering is load-bearing, same as bedrock.mjs: the SHARED eligibility gate
 * + projection (eligibility.mjs — byte-synced with horse-power, do not touch)
 * run FIRST on the chat-shaped body. Only then does this adapter check its
 * own residue: projected fields the Messages API cannot express
 * (ANTHROPIC_MAPPABLE_FIELDS) skip the candidate and fall through to the
 * next one (OpenRouter).
 *
 * After translation the body gets Anthropic `cache_control` marks
 * (addCachePromptMarks — the same function the OpenRouter payload gets),
 * which is what makes first-party prompt caching pay on the direct path.
 *
 * The translated SSE feeds the SAME CostExtractor + rewriter as every other
 * upstream. Anthropic's usage is ADDITIVE (input_tokens excludes both cache
 * buckets) and arrives split across message_start (input + cache counts) and
 * message_delta (final output count) — and cost.mjs's `c.message?.usage`
 * branch deliberately discards message_start numbers — so the translator
 * synthesizes ONE OpenAI-shaped usage frame at message_stop carrying the
 * additive numbers verbatim (keys cost.mjs parses; hp's settle path folds
 * them under the 'additive' convention, cache-write premium included).
 */
import { randomBytes } from 'node:crypto';
import { evaluateDirectEligibility, projectAllowedFields } from './eligibility.mjs';
import { addCachePromptMarks } from './routing.mjs';
import { candidateToRow } from './upstreams.mjs';

const ANTHROPIC_VERSION = '2023-06-01';

/**
 * When a chat client omits max_tokens (legal on /chat/completions, required
 * by /v1/messages), cap generation here rather than skipping the candidate.
 * 8192 covers every non-pathological chat turn; a client that wants more
 * simply sends max_tokens and it passes through.
 */
const DEFAULT_MAX_TOKENS = 8192;

/**
 * The projected (already-allowlisted) chat fields this adapter can express on
 * /v1/messages. Anything else in the projected body — response_format, n,
 * seed, sampling penalties, logprobs, logit_bias, min_p, parallel_tool_calls
 * — makes THIS CANDIDATE skip, not the request fail: OpenRouter still serves
 * it. Deliberately local to the adapter, NOT eligibility.mjs.
 */
export const ANTHROPIC_MAPPABLE_FIELDS = new Set([
  'model', // becomes the Messages `model` (catalog row id, e.g. claude-sonnet-4-6)
  'messages',
  'stream', // pass-through (the SSE translation below requires it true)
  'stream_options', // consumed: an OpenAI-ism; usage rides message_start/_delta
  'temperature',
  'top_p',
  'top_k', // natively supported on /v1/messages (unlike the Responses API)
  'max_tokens',
  'max_completion_tokens', // wins over max_tokens, like the other adapters
  'stop', // → stop_sequences
  'tools',
  'tool_choice',
  'service_tier', // row-originated; forwarded only for API-valid values (below)
  'user', // dropped: an OpenAI-side tracking id with no /messages equivalent
  'reasoning_effort', // → thinking { budget_tokens } (see THINKING_BUDGETS)
]);

/**
 * Effort → thinking budget, in tokens.
 *
 * The chat dialects express reasoning as an effort ENUM; /v1/messages wants a
 * token BUDGET, so the mapping is a judgment call — the same kind the frontend
 * already makes for Qwen. Anthropic's floor is 1024; below that, thinking must
 * stay off entirely rather than be silently requested and rejected.
 */
const THINKING_BUDGETS = { low: 1024, medium: 4096, high: 16384 };
const MIN_THINKING_BUDGET = 1024;

/**
 * Tokens reserved for the visible answer. `budget_tokens` must be strictly less
 * than `max_tokens` — the budget is carved OUT of it — so without headroom a
 * request could spend its whole allowance thinking and stream back nothing.
 */
const ANSWER_HEADROOM_TOKENS = 2048;

// The Messages API's accepted service_tier values. The projected value comes
// from OUR catalog row (projectAllowedFields injects row.serviceTier — never
// client input), but catalog tiers are provider-specific ('priority' is a
// Fireworks value), so anything outside this set skips the candidate rather
// than 400ing upstream or silently dropping a tier the row's rates assume.
const ANTHROPIC_SERVICE_TIERS = new Set(['auto', 'standard_only']);

const skip = (reason, offendingField) =>
  offendingField ? { skip: reason, offendingField } : { skip: reason };

/** Chat message content (string | text-part array) → Anthropic text blocks, or null on uncleared shapes. */
function contentToBlocks(content) {
  if (typeof content === 'string') {
    return content === '' ? [] : [{ type: 'text', text: content }];
  }
  if (Array.isArray(content)) {
    const blocks = [];
    for (const part of content) {
      // Eligibility already bailed non-text parts (non_text_content); anything
      // else here is a shape we did not clear — refuse the candidate.
      if (part?.type !== 'text' || typeof part.text !== 'string') return null;
      if (part.text !== '') blocks.push({ type: 'text', text: part.text });
    }
    return blocks;
  }
  if (content === null || content === undefined) return [];
  return null;
}

/**
 * Projected chat-completions body → /v1/messages request body, or a skip
 * reason. Returns { body } | { skip, offendingField? }.
 */
export function toMessagesRequest(projected) {
  for (const key of Object.keys(projected)) {
    if (!ANTHROPIC_MAPPABLE_FIELDS.has(key)) {
      return skip('anthropic_unmappable_field', key);
    }
  }
  // The adapter only speaks streaming SSE; a non-streaming chat response
  // shape is a different translation this candidate does not offer.
  if (projected.stream !== true) return skip('anthropic_stream_only');

  const source = Array.isArray(projected.messages) ? projected.messages : [];
  const system = [];
  const turns = []; // {role: 'user'|'assistant', content: block[]}

  let inLeadingSystem = true;
  for (const message of source) {
    const role = message?.role;
    if (role === 'system' || role === 'developer') {
      // The Messages API takes `system` as a top-level block array with no
      // position in the turn list. Only LEADING system messages translate
      // faithfully; one mid-conversation would silently move — refuse instead.
      if (!inLeadingSystem) return skip('anthropic_unmappable_field', 'messages.system');
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('anthropic_unmappable_field', 'messages.content');
      system.push(...blocks);
      continue;
    }
    inLeadingSystem = false;

    if (role === 'user' || role === 'assistant') {
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('anthropic_unmappable_field', 'messages.content');
      if (role === 'assistant' && Array.isArray(message.tool_calls)) {
        for (const call of message.tool_calls) {
          if (call?.type !== 'function' || typeof call?.function?.name !== 'string') {
            return skip('anthropic_unmappable_field', 'messages.tool_calls');
          }
          // tool_use.input is a parsed OBJECT on /v1/messages, not an
          // arguments string; unparsable arguments refuse the candidate.
          let input = {};
          const args = call.function.arguments;
          if (typeof args === 'string' && args.trim() !== '') {
            try {
              input = JSON.parse(args);
            } catch {
              return skip('anthropic_unmappable_field', 'messages.tool_calls');
            }
          }
          blocks.push({
            type: 'tool_use',
            id: String(call.id ?? ''),
            name: call.function.name,
            input,
          });
        }
      }
      turns.push({ role, content: blocks });
      continue;
    }

    if (role === 'tool') {
      // Chat tool results are standalone messages; /v1/messages carries them
      // as tool_result blocks inside a USER turn.
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('anthropic_unmappable_field', 'messages.content');
      turns.push({
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: String(message.tool_call_id ?? ''),
            content: blocks.length > 0 ? blocks : [{ type: 'text', text: '' }],
          },
        ],
      });
      continue;
    }

    return skip('anthropic_unmappable_field', 'messages.role');
  }

  // The Messages API requires strict user/assistant alternation starting with
  // a user turn: merge consecutive same-role entries (parallel tool results,
  // a user message directly after tool results) into one message.
  const messages = [];
  for (const turn of turns) {
    if (turn.content.length === 0) continue; // an all-empty turn carries nothing
    const last = messages[messages.length - 1];
    if (last && last.role === turn.role) last.content.push(...turn.content);
    else messages.push({ role: turn.role, content: [...turn.content] });
  }
  if (messages.length === 0 || messages[0].role !== 'user') {
    return skip('anthropic_unmappable_field', 'messages');
  }

  const body = {
    model: projected.model,
    messages,
    // REQUIRED by the Messages API — chat clients may legally omit it.
    max_tokens:
      typeof (projected.max_completion_tokens ?? projected.max_tokens) === 'number'
        ? (projected.max_completion_tokens ?? projected.max_tokens)
        : DEFAULT_MAX_TOKENS,
    stream: true,
  };
  if (system.length > 0) body.system = system;

  // Extended thinking. Unlike every other field here this is not a rename: the
  // budget is carved OUT of max_tokens, and Anthropic rejects the sampling
  // knobs while thinking is on (temperature must be 1; top_p/top_k unsupported).
  // So enabling it has to reason about the whole request, which is exactly why
  // this lives here and not in the frontend, where the upstream isn't known yet.
  const effortKey = String(projected.reasoning_effort ?? '').toLowerCase();
  // OpenAI's 'minimal' has no Anthropic equivalent; treat it as the floor.
  const requestedBudget = THINKING_BUDGETS[effortKey === 'minimal' ? 'low' : effortKey];
  let thinkingBudget = 0;
  if (requestedBudget) {
    // Respect a client-supplied max_tokens by clamping the budget into it. When
    // the client omitted max_tokens we picked DEFAULT_MAX_TOKENS ourselves, so
    // raising it to fit the requested budget is fair game rather than an
    // override of anyone's intent.
    const clientSetMaxTokens =
      typeof (projected.max_completion_tokens ?? projected.max_tokens) === 'number';
    if (clientSetMaxTokens) {
      thinkingBudget = Math.min(requestedBudget, body.max_tokens - ANSWER_HEADROOM_TOKENS);
    } else {
      thinkingBudget = requestedBudget;
      body.max_tokens = Math.max(body.max_tokens, thinkingBudget + ANSWER_HEADROOM_TOKENS);
    }
    // Too little room to think meaningfully → leave thinking off and answer
    // normally. Sending a sub-floor budget would just 400.
    if (thinkingBudget < MIN_THINKING_BUDGET) thinkingBudget = 0;
  }

  if (thinkingBudget > 0) {
    body.thinking = { type: 'enabled', budget_tokens: thinkingBudget };
  } else {
    // Sampling knobs are only valid when thinking is OFF.
    if (typeof projected.temperature === 'number') body.temperature = projected.temperature;
    if (typeof projected.top_p === 'number') body.top_p = projected.top_p;
    if (typeof projected.top_k === 'number') body.top_k = projected.top_k;
  }
  if (projected.stop !== undefined) {
    const stops = typeof projected.stop === 'string' ? [projected.stop] : projected.stop;
    if (!Array.isArray(stops) || stops.some((s) => typeof s !== 'string')) {
      return skip('anthropic_unmappable_field', 'stop');
    }
    if (stops.length > 0) body.stop_sequences = stops;
  }
  if (projected.service_tier !== undefined) {
    if (!ANTHROPIC_SERVICE_TIERS.has(projected.service_tier)) {
      return skip('anthropic_unmappable_field', 'service_tier');
    }
    body.service_tier = projected.service_tier;
  }

  // tools/tool_choice. `tool_choice: 'none'` has no /messages equivalent —
  // omitting the tools entirely expresses the same thing.
  if (Array.isArray(projected.tools) && projected.tools.length > 0 && projected.tool_choice !== 'none') {
    const tools = [];
    for (const tool of projected.tools) {
      if (tool?.type !== 'function' || typeof tool?.function?.name !== 'string') {
        return skip('anthropic_unmappable_field', 'tools');
      }
      const spec = {
        name: tool.function.name,
        input_schema: tool.function.parameters ?? { type: 'object' },
      };
      if (typeof tool.function.description === 'string' && tool.function.description !== '') {
        spec.description = tool.function.description;
      }
      tools.push(spec);
    }
    body.tools = tools;

    const choice = projected.tool_choice;
    if (choice === undefined || choice === 'auto') {
      body.tool_choice = { type: 'auto' };
    } else if (choice === 'required') {
      body.tool_choice = { type: 'any' };
    } else if (choice?.type === 'function' && typeof choice?.function?.name === 'string') {
      body.tool_choice = { type: 'tool', name: choice.function.name };
    } else {
      return skip('anthropic_unmappable_field', 'tool_choice');
    }
  }

  // First-party prompt caching: same marks the OpenRouter payload gets
  // (messages[0] + last two user turns; #674 empty-text guard; no-op if marks
  // already exist). Applied to the TRANSLATED blocks — chat clients cannot
  // send cache_control through the chat allowlist, so this is the only place
  // the direct path can earn cache reuse.
  addCachePromptMarks(body.messages);

  return { body };
}

/**
 * Build the outbound /v1/messages request for an anthropic candidate, or a
 * skip reason — the anthropic twin of buildDirectRequest/buildBedrockRequest.
 *
 * @param ports host -> local vsock tunnel port (the enclave's registry)
 * @param keys  key_ref -> provisioned API key
 */
export function buildAnthropicRequest({ candidate, basePayload, ports, keys }) {
  const port = ports?.[candidate.host];
  const key = keys?.[candidate.key_ref];
  if (!port || !key) return skip('no_tunnel_or_key');

  const row = candidateToRow(candidate);
  const elig = evaluateDirectEligibility({
    payload: basePayload,
    path: '/chat/completions',
    modelSuffixes: [],
    row,
  });
  if (!elig.eligible) {
    return skip(elig.reason || 'ineligible', elig.offendingField);
  }

  const projected = projectAllowedFields(basePayload, row);
  const translated = toMessagesRequest(projected);
  if (translated.skip) return translated;

  const bodyStr = JSON.stringify(translated.body);
  // No anthropic-beta header: per Anthropic's context-windows doc, 1M
  // context is the DEFAULT on every model that has it ("you don't need a
  // beta header") and the old context-1m-2025-08-07 beta is retired.
  const headers = {
    host: candidate.host,
    'content-type': 'application/json',
    accept: 'text/event-stream',
    'content-length': Buffer.byteLength(bodyStr),
    // Anthropic auth is x-api-key + a pinned API version — never Bearer.
    'x-api-key': key,
    'anthropic-version': ANTHROPIC_VERSION,
  };

  return {
    provider: candidate.provider,
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
    apiStyle: 'anthropic',
    bodyStr,
    opts: {
      host: '127.0.0.1',
      port,
      servername: candidate.host,
      method: 'POST',
      path: candidate.path,
      headers,
    },
  };
}

const STOP_REASON_MAP = {
  end_turn: 'stop',
  stop_sequence: 'stop',
  max_tokens: 'length',
  tool_use: 'tool_calls',
};

/**
 * Anthropic Messages SSE → chat-completions SSE.
 *
 * feed(chunk) returns the chat-chunk bytes safe to forward now; finish()
 * returns the trailing bytes. Error events / malformed frames / truncation
 * before message_stop become a terminal OpenRouter-style `data: {"error": …}`
 * frame — after which the transform goes silent. If the stream dies before
 * message_stop, the extractor reports zero tokens and hp bills $0 (the
 * existing zero-usage posture).
 *
 * Event grammar (Anthropic Messages streaming): message_start (model + the
 * ONLY complete input/cache usage) → content_block_start/delta/stop
 * (text_delta / input_json_delta / thinking_delta) → message_delta
 * (stop_reason + cumulative output_tokens) → message_stop. `ping` may appear
 * anywhere.
 */
export class MessagesToChatSse {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.wireModel = null; // message_start echo (possibly dated) — tripwire input
    this.id = `chatcmpl-${randomBytes(8).toString('hex')}`;
    this.created = Math.floor(Date.now() / 1000);
    this.buffer = '';
    this.eventData = [];
    this.toolIndexByBlock = new Map();
    this.toolCount = 0;
    this.usage = { input_tokens: 0, output_tokens: 0 };
    this.finishReason = null;
    this.completed = false;
    this.doneEmitted = false;
    this.fatal = false;
    this.decoder = new TextDecoder();
  }

  _chunk(delta, finishReason = null) {
    return (
      'data: ' +
      JSON.stringify({
        id: this.id,
        object: 'chat.completion.chunk',
        created: this.created,
        model: this.model,
        choices: [{ index: 0, delta, finish_reason: finishReason }],
      }) +
      '\n\n'
    );
  }

  _error(message) {
    this.fatal = true;
    return 'data: ' + JSON.stringify({ error: { message, code: 502 } }) + '\n\n';
  }

  feed(chunk) {
    if (this.fatal || this.doneEmitted) return Buffer.alloc(0);
    this.buffer += this.decoder.decode(chunk, { stream: true });
    let out = '';
    let idx;
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, '');
      this.buffer = this.buffer.slice(idx + 1);
      if (line === '') {
        if (this.eventData.length > 0) {
          out += this._dispatch(this.eventData.join('\n'));
          this.eventData = [];
        }
        if (this.fatal || this.doneEmitted) break;
        continue;
      }
      if (line.startsWith('data:')) {
        this.eventData.push(line.slice(5).trimStart());
      }
      // event:/id: lines carry no payload we need — .type is in the data.
    }
    return Buffer.from(out, 'utf8');
  }

  _dispatch(data) {
    let event;
    try {
      event = JSON.parse(data);
    } catch {
      return this._error('anthropic stream frame was not JSON');
    }

    switch (event?.type) {
      case 'message_start': {
        const message = event.message ?? {};
        if (typeof message.model === 'string') this.wireModel = message.model;
        // The ONLY event carrying complete input-side usage. Additive
        // convention: input_tokens EXCLUDES both cache buckets. cost.mjs's
        // c.message?.usage branch would discard these — hence the synthesized
        // frame at message_stop below.
        const usage = message.usage ?? {};
        this.usage = {
          input_tokens: Number(usage.input_tokens ?? 0),
          output_tokens: Number(usage.output_tokens ?? 0),
          ...(usage.cache_read_input_tokens !== undefined
            ? { cache_read_input_tokens: Number(usage.cache_read_input_tokens) }
            : {}),
          ...(usage.cache_creation_input_tokens !== undefined
            ? { cache_creation_input_tokens: Number(usage.cache_creation_input_tokens) }
            : {}),
        };
        return this._chunk({ role: 'assistant', content: '' });
      }

      case 'content_block_start': {
        const block = event.content_block;
        if (block?.type !== 'tool_use') return '';
        const index = this.toolCount++;
        this.toolIndexByBlock.set(event.index, index);
        return this._chunk({
          tool_calls: [
            {
              index,
              id: String(block.id ?? ''),
              type: 'function',
              function: { name: block.name ?? '', arguments: '' },
            },
          ],
        });
      }

      case 'content_block_delta': {
        const delta = event.delta;
        if (delta?.type === 'text_delta') {
          return typeof delta.text === 'string' && delta.text !== ''
            ? this._chunk({ content: delta.text })
            : '';
        }
        if (delta?.type === 'input_json_delta') {
          const index = this.toolIndexByBlock.get(event.index);
          if (index === undefined || typeof delta.partial_json !== 'string') return '';
          return this._chunk({
            tool_calls: [{ index, function: { arguments: delta.partial_json } }],
          });
        }
        return ''; // thinking_delta / signature_delta — no chat equivalent
      }

      case 'message_delta': {
        if (typeof event.delta?.stop_reason === 'string') {
          this.finishReason = STOP_REASON_MAP[event.delta.stop_reason] || 'stop';
        }
        // Cumulative for the turn — last write wins, matching the API.
        if (typeof event.usage?.output_tokens === 'number') {
          this.usage.output_tokens = event.usage.output_tokens;
        }
        return '';
      }

      case 'message_stop': {
        this.completed = true;
        let out = this._chunk({}, this.finishReason ?? 'stop');
        // Synthesized usage frame: additive numbers VERBATIM under the keys
        // cost.mjs parses; `model` is the wire echo (possibly dated) so the
        // served-model tripwire sees what actually served. The extractor
        // reads this pre-rewrite; the client-visible copy is rewritten to the
        // public slug like everything else.
        const frame = {
          id: this.id,
          object: 'chat.completion.chunk',
          created: this.created,
          model: this.wireModel ?? this.model,
          choices: [],
          usage: this.usage,
        };
        out += 'data: ' + JSON.stringify(frame) + '\n\n';
        this.doneEmitted = true;
        return out + 'data: [DONE]\n\n';
      }

      case 'error': {
        const detail = event.error?.message || event.error?.type || 'stream error';
        return this._error(`anthropic ${detail}`);
      }

      default:
        return ''; // ping, content_block_stop, forward-compat events
    }
  }

  finish() {
    if (this.fatal || this.doneEmitted) return Buffer.alloc(0);
    // Ended before message_stop: surface it as an error so the client does
    // not mistake a partial answer for a complete one.
    return Buffer.from(this._error('anthropic stream ended unexpectedly'), 'utf8');
  }
}
