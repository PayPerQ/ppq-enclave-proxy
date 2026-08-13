/**
 * AWS Bedrock direct upstream — the `api_style: 'bedrock'` adapter.
 *
 * The client speaks OpenAI /chat/completions; Bedrock speaks the Converse API
 * (ConverseStream: model id in the URL path, SigV4 auth, binary eventstream
 * response). This module owns the whole translation:
 *
 *   request : projected OpenAI body ──toConverseRequest──▶ Converse JSON
 *   response: eventstream frames ──EventStreamToSse──▶ OpenAI-shaped SSE
 *
 * Ordering is load-bearing: the SHARED eligibility gate + projection
 * (eligibility.mjs — byte-synced with horse-power, do not touch) run FIRST on
 * the OpenAI-shaped body, exactly as for Fireworks. Only then does this
 * adapter check its own residue: projected fields Converse cannot express
 * (BEDROCK_MAPPABLE_FIELDS) skip the candidate and fall through to the next
 * one (OpenRouter). That keeps the conformance-pinned eligibility contract
 * frozen while Bedrock's narrower surface stays fail-safe.
 *
 * The translated SSE is fed to the SAME CostExtractor + rewriter the other
 * upstreams use: the usage frame below speaks the Anthropic-style additive
 * names cost.mjs already parses (input_tokens EXCLUDES cache reads — hp's
 * settle folds them via its additive-usage convention), and carries
 * `model: <upstream_model>` so the served-model tripwire sees the wire id
 * while the rewriter hides it from the client.
 */
import { randomBytes } from 'node:crypto';
import { evaluateDirectEligibility, projectAllowedFields } from './eligibility.mjs';
import { candidateToRow } from './upstreams.mjs';
import { signRequest } from './sigv4.mjs';
import { EventStreamParser } from './eventstream.mjs';

/**
 * The projected (already-allowlisted) OpenAI fields this adapter can express
 * in a Converse request. Anything else present in the projected body —
 * response_format (even json_object), n, seed, sampling penalties, logprobs,
 * logit_bias, min_p, top_k, parallel_tool_calls — makes THIS CANDIDATE skip,
 * not the request fail: OpenRouter still serves it. Deliberately local to the
 * adapter, NOT part of eligibility.mjs (see module header).
 */
export const BEDROCK_MAPPABLE_FIELDS = new Set([
  'model', // consumed: the model id rides in the URL path, never the body
  'messages',
  'stream', // consumed: streaming is the endpoint (converse-stream)
  'stream_options', // consumed: Converse always emits the usage metadata event
  'temperature',
  'top_p',
  'max_tokens',
  'max_completion_tokens',
  'stop',
  'tools',
  'tool_choice',
  'reasoning_effort', // forwarded via additionalModelRequestFields — UNVERIFIED upstream support
  'user', // dropped: an OpenAI-side tracking id with no Converse equivalent
]);

const skip = (reason, offendingField) =>
  offendingField ? { skip: reason, offendingField } : { skip: reason };

/** OpenAI message content (string | text-part array) → array of Converse text blocks. */
function contentToBlocks(content) {
  if (typeof content === 'string') {
    return content === '' ? [] : [{ text: content }];
  }
  if (Array.isArray(content)) {
    const blocks = [];
    for (const part of content) {
      // Eligibility has already bailed non-text parts (non_text_content);
      // anything else here is a shape we did not clear — refuse the candidate.
      if (part?.type !== 'text' || typeof part.text !== 'string') return null;
      if (part.text !== '') blocks.push({ text: part.text });
    }
    return blocks;
  }
  if (content === null || content === undefined) return [];
  return null;
}

/**
 * Projected OpenAI body → Converse request body, or a skip reason.
 * Returns { body } | { skip, offendingField? }.
 */
export function toConverseRequest(projected) {
  for (const key of Object.keys(projected)) {
    if (!BEDROCK_MAPPABLE_FIELDS.has(key)) {
      return skip('bedrock_unmappable_field', key);
    }
  }
  // The adapter only speaks ConverseStream; a non-streaming OpenAI response
  // shape is a different translation this candidate does not offer.
  if (projected.stream !== true) return skip('bedrock_stream_only');

  const source = Array.isArray(projected.messages) ? projected.messages : [];
  const system = [];
  const turns = []; // {role: 'user'|'assistant', content: block[]}

  let inLeadingSystem = true;
  for (const message of source) {
    const role = message?.role;
    if (role === 'system') {
      // Converse `system` is a top-level array with no position in the turn
      // list. Only LEADING system messages translate faithfully; one mid-
      // conversation would silently move, so refuse the candidate instead.
      if (!inLeadingSystem) return skip('bedrock_unmappable_field', 'messages.system');
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('bedrock_unmappable_field', 'messages.content');
      system.push(...blocks);
      continue;
    }
    inLeadingSystem = false;

    if (role === 'user' || role === 'assistant') {
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('bedrock_unmappable_field', 'messages.content');
      if (role === 'assistant' && Array.isArray(message.tool_calls)) {
        for (const call of message.tool_calls) {
          if (call?.type !== 'function' || typeof call?.function?.name !== 'string') {
            return skip('bedrock_unmappable_field', 'messages.tool_calls');
          }
          let input = {};
          const args = call.function.arguments;
          if (typeof args === 'string' && args.trim() !== '') {
            try {
              input = JSON.parse(args);
            } catch {
              return skip('bedrock_unmappable_field', 'messages.tool_calls');
            }
          }
          blocks.push({
            toolUse: { toolUseId: String(call.id ?? ''), name: call.function.name, input },
          });
        }
      }
      turns.push({ role, content: blocks });
      continue;
    }

    if (role === 'tool') {
      // OpenAI tool results are standalone messages; Converse carries them as
      // toolResult blocks in a USER turn.
      const blocks = contentToBlocks(message.content);
      if (blocks === null) return skip('bedrock_unmappable_field', 'messages.content');
      turns.push({
        role: 'user',
        content: [
          {
            toolResult: {
              toolUseId: String(message.tool_call_id ?? ''),
              content: blocks.length > 0 ? blocks : [{ text: '' }],
            },
          },
        ],
      });
      continue;
    }

    return skip('bedrock_unmappable_field', 'messages.role');
  }

  // Converse requires strictly alternating user/assistant turns; merge
  // consecutive same-role entries (e.g. parallel tool results, or a user
  // message directly after tool results).
  const messages = [];
  for (const turn of turns) {
    const last = messages[messages.length - 1];
    if (last && last.role === turn.role) last.content.push(...turn.content);
    else messages.push({ role: turn.role, content: [...turn.content] });
  }
  if (messages.length === 0) return skip('bedrock_unmappable_field', 'messages');

  const body = { messages };
  if (system.length > 0) body.system = system;

  const inferenceConfig = {};
  const maxTokens = projected.max_completion_tokens ?? projected.max_tokens;
  if (typeof maxTokens === 'number') inferenceConfig.maxTokens = maxTokens;
  if (typeof projected.temperature === 'number') inferenceConfig.temperature = projected.temperature;
  if (typeof projected.top_p === 'number') inferenceConfig.topP = projected.top_p;
  if (projected.stop !== undefined) {
    const stops = typeof projected.stop === 'string' ? [projected.stop] : projected.stop;
    if (!Array.isArray(stops) || stops.some((s) => typeof s !== 'string')) {
      return skip('bedrock_unmappable_field', 'stop');
    }
    if (stops.length > 0) inferenceConfig.stopSequences = stops;
  }
  if (Object.keys(inferenceConfig).length > 0) body.inferenceConfig = inferenceConfig;

  // tools/tool_choice → toolConfig. `tool_choice: 'none'` disables tools
  // entirely, which Converse expresses by having no toolConfig at all.
  if (Array.isArray(projected.tools) && projected.tools.length > 0 && projected.tool_choice !== 'none') {
    const tools = [];
    for (const tool of projected.tools) {
      if (tool?.type !== 'function' || typeof tool?.function?.name !== 'string') {
        return skip('bedrock_unmappable_field', 'tools');
      }
      const toolSpec = {
        name: tool.function.name,
        inputSchema: { json: tool.function.parameters ?? {} },
      };
      if (typeof tool.function.description === 'string' && tool.function.description !== '') {
        toolSpec.description = tool.function.description;
      }
      tools.push({ toolSpec });
    }
    const toolConfig = { tools };
    const choice = projected.tool_choice;
    if (choice === undefined || choice === 'auto') {
      toolConfig.toolChoice = { auto: {} };
    } else if (choice === 'required') {
      toolConfig.toolChoice = { any: {} };
    } else if (choice?.type === 'function' && typeof choice?.function?.name === 'string') {
      toolConfig.toolChoice = { tool: { name: choice.function.name } };
    } else {
      return skip('bedrock_unmappable_field', 'tool_choice');
    }
    body.toolConfig = toolConfig;
  }

  if (projected.reasoning_effort !== undefined) {
    body.additionalModelRequestFields = { reasoning_effort: projected.reasoning_effort };
  }

  return { body };
}

/**
 * Build the outbound ConverseStream request for a bedrock candidate, or a
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
  const converse = toConverseRequest(projected);
  if (converse.skip) return converse;

  const bodyStr = JSON.stringify(converse.body);
  const signed = signRequest({
    method: 'POST',
    host: candidate.host,
    path: candidate.path,
    body: bodyStr,
    signHeaders: { 'content-type': 'application/json' },
    region,
    service: 'bedrock',
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
        accept: 'application/vnd.amazon.eventstream',
        'content-length': Buffer.byteLength(bodyStr),
        ...signed,
      },
    },
  };
}

const STOP_REASON_MAP = {
  end_turn: 'stop',
  stop_sequence: 'stop',
  max_tokens: 'length',
  tool_use: 'tool_calls',
  guardrail_intervened: 'content_filter',
  content_filtered: 'content_filter',
};

/**
 * ConverseStream eventstream → OpenAI-shaped SSE text.
 *
 * feed(chunk) returns the SSE bytes safe to forward now; finish() returns the
 * trailing bytes ([DONE], or an error frame for a stream truncated
 * mid-frame). Corruption (CRC/structural) and exception events become a
 * terminal OpenRouter-style `data: {"error": …}` frame — the same surface an
 * OpenRouter mid-stream death has today — after which the transform goes
 * silent. If the stream dies before the usage metadata event, the extractor
 * reports zero tokens and hp bills $0 (the existing zero-usage posture).
 */
export class EventStreamToSse {
  constructor({ upstreamModel }) {
    this.parser = new EventStreamParser();
    this.model = upstreamModel;
    this.id = `chatcmpl-${randomBytes(8).toString('hex')}`;
    this.created = Math.floor(Date.now() / 1000);
    this.toolIndexByBlock = new Map();
    this.toolCount = 0;
    this.finished = false; // saw messageStop
    this.doneEmitted = false;
    this.fatal = false;
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
    let messages;
    try {
      messages = this.parser.feed(chunk);
    } catch (err) {
      return Buffer.from(this._error(`bedrock stream corrupted: ${err.message}`), 'utf8');
    }
    let out = '';
    for (const message of messages) {
      if (this.fatal) break;
      out += this._event(message);
    }
    return Buffer.from(out, 'utf8');
  }

  _event({ headers, payload }) {
    const messageType = headers[':message-type'];
    if (messageType === 'exception' || messageType === 'error') {
      const type = headers[':exception-type'] || headers[':error-code'] || 'exception';
      let detail = '';
      try {
        detail = JSON.parse(payload.toString('utf8'))?.message || '';
      } catch {
        /* opaque payload */
      }
      return this._error(`bedrock ${type}${detail ? `: ${detail}` : ''}`);
    }
    if (messageType !== 'event') return '';

    let event;
    try {
      event = JSON.parse(payload.toString('utf8'));
    } catch {
      return this._error('bedrock event payload was not JSON');
    }

    switch (headers[':event-type']) {
      case 'messageStart':
        return this._chunk({ role: 'assistant', content: '' });

      case 'contentBlockStart': {
        const toolUse = event?.start?.toolUse;
        if (!toolUse) return '';
        const index = this.toolCount++;
        this.toolIndexByBlock.set(event.contentBlockIndex, index);
        return this._chunk({
          tool_calls: [
            {
              index,
              id: toolUse.toolUseId,
              type: 'function',
              function: { name: toolUse.name, arguments: '' },
            },
          ],
        });
      }

      case 'contentBlockDelta': {
        const delta = event?.delta;
        if (typeof delta?.text === 'string') {
          return delta.text === '' ? '' : this._chunk({ content: delta.text });
        }
        if (typeof delta?.toolUse?.input === 'string') {
          const index = this.toolIndexByBlock.get(event.contentBlockIndex);
          if (index === undefined) return '';
          return this._chunk({
            tool_calls: [{ index, function: { arguments: delta.toolUse.input } }],
          });
        }
        return ''; // reasoningContent etc. — nothing to surface on this dialect
      }

      case 'contentBlockStop':
        return '';

      case 'messageStop': {
        this.finished = true;
        const reason = STOP_REASON_MAP[event?.stopReason] || 'stop';
        return this._chunk({}, reason);
      }

      case 'metadata': {
        const usage = event?.usage || {};
        // Additive names, verbatim from Bedrock: input_tokens EXCLUDES cache
        // reads/writes. cost.mjs parses these exact keys; hp's settle path
        // folds them under the bedrock usage convention before pricing.
        const frame = {
          id: this.id,
          object: 'chat.completion.chunk',
          created: this.created,
          model: this.model,
          choices: [],
          usage: {
            input_tokens: Number(usage.inputTokens ?? 0),
            output_tokens: Number(usage.outputTokens ?? 0),
            ...(usage.cacheReadInputTokens !== undefined
              ? { cache_read_input_tokens: Number(usage.cacheReadInputTokens) }
              : {}),
            // cost.mjs parses the Anthropic spelling for cache WRITES.
            ...(usage.cacheWriteInputTokens !== undefined
              ? { cache_creation_input_tokens: Number(usage.cacheWriteInputTokens) }
              : {}),
          },
        };
        this.doneEmitted = true;
        return 'data: ' + JSON.stringify(frame) + '\n\ndata: [DONE]\n\n';
      }

      default:
        return ''; // unknown event types are forward-compat noise, not errors
    }
  }

  finish() {
    if (this.fatal || this.doneEmitted) return Buffer.alloc(0);
    if (this.parser.hasPartial() || !this.finished) {
      // Truncated mid-frame or before messageStop: surface it as an error so
      // the client does not mistake a partial answer for a complete one.
      return Buffer.from(this._error('bedrock stream ended unexpectedly'), 'utf8');
    }
    this.doneEmitted = true;
    return Buffer.from('data: [DONE]\n\n', 'utf8');
  }
}
