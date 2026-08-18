/**
 * AWS Bedrock direct upstream — the `api_style: 'bedrock'` adapter.
 *
 * The OpenAI frontier models on Bedrock are served ONLY by the OpenAI
 * RESPONSES API on the bedrock-mantle endpoint (live-probed 2026-08-14
 * against account 287432920037 — Converse, ConverseStream, InvokeModel and
 * bedrock-runtime all fail for them; see horse-power
 * services/directProviders/bedrockUsage.fixtures.json for raw traces):
 *
 *   POST https://bedrock-mantle.{region}.api.aws/openai/v1/responses
 *   SigV4 service name 'bedrock-mantle', streaming = plain SSE.
 *
 * The client speaks OpenAI /chat/completions; this module owns the two-way
 * translation to the (also-OpenAI, but different) Responses dialect:
 *
 *   request : projected chat body ──toResponsesRequest──▶ Responses JSON
 *   response: Responses SSE events ──ResponsesToChatSse──▶ chat-chunk SSE
 *
 * Ordering is load-bearing: the SHARED eligibility gate + projection
 * (eligibility.mjs — byte-synced with horse-power, do not touch) run FIRST on
 * the chat-shaped body, exactly as for Fireworks. Only then does this adapter
 * check its own residue: projected fields the Responses API cannot express
 * (BEDROCK_MAPPABLE_FIELDS) skip the candidate and fall through to the next
 * one (OpenRouter). That keeps the conformance-pinned eligibility contract
 * frozen while Bedrock's different surface stays fail-safe.
 *
 * The translated SSE is fed to the SAME CostExtractor + rewriter the other
 * upstreams use: the usage frame passes Bedrock's numbers through VERBATIM
 * (input_tokens / output_tokens / input_tokens_details.{cached_tokens,
 * cache_write_tokens} — the subset convention cost.mjs already parses, and
 * exactly what hp's settle path prices, including the cache-write premium),
 * and carries `model` so the served-model tripwire sees the wire id while
 * the rewriter hides it from the client.
 */
import { randomBytes } from 'node:crypto';
import { evaluateDirectEligibility, projectAllowedFields } from './eligibility.mjs';
import { candidateToRow } from './upstreams.mjs';
import { signRequest } from './sigv4.mjs';

/**
 * The projected (already-allowlisted) chat fields this adapter can express in
 * a Responses API request. Anything else present in the projected body —
 * response_format, stop (the Responses API has no stop sequences), n, seed,
 * sampling penalties, logprobs, logit_bias, min_p, top_k — makes THIS
 * CANDIDATE skip, not the request fail: OpenRouter still serves it.
 * Deliberately local to the adapter, NOT part of eligibility.mjs (see module
 * header).
 */
export const BEDROCK_MAPPABLE_FIELDS = new Set([
  'model', // becomes the Responses `model` (bare Bedrock id, e.g. openai.gpt-5.5)
  'messages',
  'stream', // pass-through (the SSE translation below requires it true)
  'stream_options', // consumed: Responses reports usage on response.completed
  'temperature',
  'top_p',
  'max_tokens',
  'max_completion_tokens', // → max_output_tokens
  'tools',
  'tool_choice',
  'parallel_tool_calls', // Responses supports it natively (Converse did not)
  'reasoning_effort', // → reasoning: { effort }
  'service_tier', // row-originated; forwarded only for API-valid values (below)
  'user', // dropped: an OpenAI-side tracking id; mantle has no equivalent
]);

// The Responses API's accepted service_tier values (mantle probe recorded
// defaultServiceTier 'auto'). Same posture as the anthropic adapter: the
// value comes from OUR catalog row, but catalog tiers are provider-specific,
// so anything outside this set skips the candidate rather than 400ing
// upstream or silently dropping a tier the row's rates assume.
const BEDROCK_SERVICE_TIERS = new Set(['auto', 'default', 'flex', 'priority']);

const skip = (reason, offendingField) =>
  offendingField ? { skip: reason, offendingField } : { skip: reason };

/** Chat message content (string | text-part array) → plain text, or null on shapes we didn't clear. */
function contentToText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const parts = [];
    for (const part of content) {
      // Eligibility already bailed non-text parts (non_text_content); anything
      // else here is a shape we did not clear — refuse the candidate.
      if (part?.type !== 'text' || typeof part.text !== 'string') return null;
      parts.push(part.text);
    }
    return parts.join('');
  }
  if (content === null || content === undefined) return '';
  return null;
}

/**
 * Projected chat-completions body → Responses API request body, or a skip
 * reason. Returns { body } | { skip, offendingField? }.
 */
export function toResponsesRequest(projected) {
  for (const key of Object.keys(projected)) {
    if (!BEDROCK_MAPPABLE_FIELDS.has(key)) {
      return skip('bedrock_unmappable_field', key);
    }
  }
  // The adapter only speaks streaming SSE; a non-streaming chat response
  // shape is a different translation this candidate does not offer.
  if (projected.stream !== true) return skip('bedrock_stream_only');

  const source = Array.isArray(projected.messages) ? projected.messages : [];
  const input = [];
  for (const message of source) {
    const role = message?.role;
    if (role === 'system' || role === 'developer' || role === 'user' || role === 'assistant') {
      const text = contentToText(message.content);
      if (text === null) return skip('bedrock_unmappable_field', 'messages.content');
      if (text !== '') {
        input.push({
          role,
          // Typed content items: input_text for what we SEND the model,
          // output_text for what the model previously SAID (assistant turns).
          content: [{ type: role === 'assistant' ? 'output_text' : 'input_text', text }],
        });
      }
      if (role === 'assistant' && Array.isArray(message.tool_calls)) {
        for (const call of message.tool_calls) {
          if (call?.type !== 'function' || typeof call?.function?.name !== 'string') {
            return skip('bedrock_unmappable_field', 'messages.tool_calls');
          }
          input.push({
            type: 'function_call',
            call_id: String(call.id ?? ''),
            name: call.function.name,
            arguments: typeof call.function.arguments === 'string' ? call.function.arguments : '{}',
          });
        }
      }
      continue;
    }
    if (role === 'tool') {
      const text = contentToText(message.content);
      if (text === null) return skip('bedrock_unmappable_field', 'messages.content');
      input.push({
        type: 'function_call_output',
        call_id: String(message.tool_call_id ?? ''),
        output: text,
      });
      continue;
    }
    return skip('bedrock_unmappable_field', 'messages.role');
  }
  if (input.length === 0) return skip('bedrock_unmappable_field', 'messages');

  const body = {
    model: projected.model,
    input,
    stream: true,
    // PRIVACY: the Responses API persists responses by default (`store`
    // defaults true). This proxy exists so content never rests outside the
    // enclave — always opt out.
    store: false,
  };

  const maxTokens = projected.max_completion_tokens ?? projected.max_tokens;
  if (typeof maxTokens === 'number') body.max_output_tokens = maxTokens;
  if (typeof projected.temperature === 'number') body.temperature = projected.temperature;
  if (typeof projected.top_p === 'number') body.top_p = projected.top_p;
  if (typeof projected.parallel_tool_calls === 'boolean') {
    body.parallel_tool_calls = projected.parallel_tool_calls;
  }
  if (projected.service_tier !== undefined) {
    if (!BEDROCK_SERVICE_TIERS.has(projected.service_tier)) {
      return skip('bedrock_unmappable_field', 'service_tier');
    }
    body.service_tier = projected.service_tier;
  }
  if (projected.reasoning_effort !== undefined) {
    body.reasoning = { effort: projected.reasoning_effort };
  }

  if (Array.isArray(projected.tools) && projected.tools.length > 0) {
    const tools = [];
    for (const tool of projected.tools) {
      if (tool?.type !== 'function' || typeof tool?.function?.name !== 'string') {
        return skip('bedrock_unmappable_field', 'tools');
      }
      const flat = {
        type: 'function',
        name: tool.function.name,
        parameters: tool.function.parameters ?? {},
        // Chat-completions tools never enforced strict schemas; strict mode
        // 400s on schemas without additionalProperties:false, which arbitrary
        // caller schemas won't satisfy. Preserve chat behavior explicitly.
        strict: false,
      };
      if (typeof tool.function.description === 'string' && tool.function.description !== '') {
        flat.description = tool.function.description;
      }
      tools.push(flat);
    }
    body.tools = tools;

    const choice = projected.tool_choice;
    if (choice === undefined) {
      // Responses default is auto; leave unset.
    } else if (choice === 'auto' || choice === 'none' || choice === 'required') {
      body.tool_choice = choice;
    } else if (choice?.type === 'function' && typeof choice?.function?.name === 'string') {
      body.tool_choice = { type: 'function', name: choice.function.name };
    } else {
      return skip('bedrock_unmappable_field', 'tool_choice');
    }
  }

  return { body };
}

/**
 * Build the outbound Responses API request for a bedrock candidate, or a
 * skip reason — the bedrock twin of upstreams.mjs buildDirectRequest.
 *
 * @param ports host -> local vsock tunnel port (the enclave's registry)
 * @param creds {accessKeyId, secretAccessKey, sessionToken?, expiration?} or null
 */
export function buildBedrockRequest({ candidate, basePayload, ports, creds, now = new Date() }) {
  const port = ports?.[candidate.host];
  if (!port || !creds) return skip('no_tunnel_or_key');
  // Refuse to sign with credentials about to expire mid-request; the host's
  // refresh timer will have replaced them by the next attempt.
  if (creds.expiration instanceof Date && creds.expiration.getTime() - now.getTime() < 60_000) {
    return skip('bedrock_creds_expired');
  }
  const region = candidate.region;
  if (typeof region !== 'string' || !/^[a-z0-9][a-z0-9-]{0,30}$/.test(region)) {
    return skip('no_region');
  }

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
  const responses = toResponsesRequest(projected);
  if (responses.skip) return responses;

  const bodyStr = JSON.stringify(responses.body);
  const signed = signRequest({
    method: 'POST',
    host: candidate.host,
    path: candidate.path,
    body: bodyStr,
    signHeaders: { 'content-type': 'application/json' },
    region,
    // Probed: the mantle endpoint signs under its OWN service name, not
    // 'bedrock' — the classic mistake would be a 403 with a confusing scope.
    service: 'bedrock-mantle',
    creds,
    now,
  });

  return {
    provider: candidate.provider,
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
    apiStyle: 'bedrock',
    bodyStr,
    opts: {
      host: '127.0.0.1',
      port,
      servername: candidate.host,
      method: 'POST',
      path: candidate.path,
      headers: {
        host: candidate.host,
        'content-type': 'application/json',
        accept: 'text/event-stream',
        'content-length': Buffer.byteLength(bodyStr),
        ...signed,
      },
    },
  };
}

/**
 * Responses API SSE → chat-completions SSE.
 *
 * feed(chunk) returns the chat-chunk SSE bytes safe to forward now; finish()
 * returns the trailing bytes ([DONE], or an error frame for a stream that
 * ended before response.completed). Failure events and malformed frames
 * become a terminal OpenRouter-style `data: {"error": …}` frame — the same
 * surface an OpenRouter mid-stream death has today — after which the
 * transform goes silent. If the stream dies before the usage event, the
 * extractor reports zero tokens and hp bills $0 (the existing zero-usage
 * posture).
 *
 * Event sequence pinned by the live probe (bedrockUsage.fixtures.json):
 * response.created → response.in_progress → response.output_item.added →
 * response.content_part.added → response.output_text.delta* →
 * … → response.completed (usage null until the terminal event). Function-call
 * events (response.output_item.added item.type='function_call',
 * response.function_call_arguments.delta) follow the OpenAI Responses spec —
 * not yet probed on mantle (the probe ran no tool calls).
 */
export class ResponsesToChatSse {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.id = `chatcmpl-${randomBytes(8).toString('hex')}`;
    this.created = Math.floor(Date.now() / 1000);
    this.buffer = '';
    this.eventData = [];
    this.toolIndexByItem = new Map();
    this.toolCount = 0;
    this.sawToolCall = false;
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
    // SSE framing: field lines accumulate until a blank line dispatches the
    // event. Only `data:` carries payload here; the probe shows the event
    // name rides both the `event:` field and the payload's own `type`.
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
      // event:/id:/retry: lines carry no payload we need — .type is in the data.
    }
    return Buffer.from(out, 'utf8');
  }

  _dispatch(data) {
    if (data === '[DONE]') return ''; // not part of the Responses protocol; tolerate
    let event;
    try {
      event = JSON.parse(data);
    } catch {
      return this._error('bedrock stream frame was not JSON');
    }

    switch (event?.type) {
      case 'response.created':
        return this._chunk({ role: 'assistant', content: '' });

      case 'response.output_item.added': {
        const item = event.item;
        if (item?.type !== 'function_call') return '';
        this.sawToolCall = true;
        const index = this.toolCount++;
        this.toolIndexByItem.set(item.id ?? event.output_index, index);
        return this._chunk({
          tool_calls: [
            {
              index,
              id: String(item.call_id ?? item.id ?? ''),
              type: 'function',
              function: { name: item.name ?? '', arguments: '' },
            },
          ],
        });
      }

      case 'response.function_call_arguments.delta': {
        const index =
          this.toolIndexByItem.get(event.item_id) ?? this.toolIndexByItem.get(event.output_index);
        if (index === undefined || typeof event.delta !== 'string') return '';
        return this._chunk({
          tool_calls: [{ index, function: { arguments: event.delta } }],
        });
      }

      case 'response.output_text.delta':
        return typeof event.delta === 'string' && event.delta !== ''
          ? this._chunk({ content: event.delta })
          : '';

      case 'response.completed':
      case 'response.incomplete': {
        this.completed = true;
        const response = event.response ?? {};
        const finishReason =
          event.type === 'response.incomplete' &&
          response?.incomplete_details?.reason === 'max_output_tokens'
            ? 'length'
            : this.sawToolCall
              ? 'tool_calls'
              : 'stop';
        let out = this._chunk({}, finishReason);

        // Usage frame: pass Bedrock's numbers through VERBATIM — the subset
        // convention (both cache buckets ⊆ input_tokens) is exactly what
        // cost.mjs parses and hp's settle path prices (write premium incl.).
        const usage = response.usage;
        if (usage) {
          const frame = {
            id: this.id,
            object: 'chat.completion.chunk',
            created: this.created,
            model: typeof response.model === 'string' ? response.model : this.model,
            choices: [],
            usage: {
              input_tokens: Number(usage.input_tokens ?? 0),
              output_tokens: Number(usage.output_tokens ?? 0),
              ...(usage.input_tokens_details
                ? { input_tokens_details: usage.input_tokens_details }
                : {}),
            },
          };
          out += 'data: ' + JSON.stringify(frame) + '\n\n';
        }
        this.doneEmitted = true;
        return out + 'data: [DONE]\n\n';
      }

      case 'response.failed': {
        const message =
          event.response?.error?.message || 'bedrock response.failed with no detail';
        return this._error(`bedrock ${message}`);
      }

      case 'error':
        return this._error(`bedrock ${event.message || event.code || 'stream error'}`);

      default:
        return ''; // in_progress, content_part.*, output_text.done, … — no chat-chunk equivalent
    }
  }

  finish() {
    if (this.fatal || this.doneEmitted) return Buffer.alloc(0);
    // Ended before response.completed: surface it as an error so the client
    // does not mistake a partial answer for a complete one.
    return Buffer.from(this._error('bedrock stream ended unexpectedly'), 'utf8');
  }
}
