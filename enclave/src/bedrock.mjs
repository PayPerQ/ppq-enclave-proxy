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
import { computeSafetyIdentifier } from './routing.mjs';

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
  // DROPPED, not forwarded (probed 2026-09-10, mirror of hp): sol/terra/
  // luna/5.5/astra answer 400 `Unsupported parameter: 'temperature'` for any
  // temperature other than 1, and likewise for any top_p (5.4 alone accepts
  // them). OpenRouter's OpenAI endpoints list neither in supported_parameters
  // and silently discard both, so dropping them reproduces what the
  // OpenRouter candidate already does — a documented no-op.
  'temperature',
  'top_p',
  'max_tokens',
  'max_completion_tokens', // → max_output_tokens
  'tools',
  'tool_choice',
  'parallel_tool_calls', // Responses supports it natively (Converse did not)
  'reasoning_effort', // → reasoning: { effort }
  'verbosity', // → text: { verbosity } (gate-validated low|medium|high; probed 2026-09-28)
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

/**
 * Data-URI image parts this adapter can express as Responses `input_image`
 * items. Narrower than the shared gate's set on purpose (the anthropic.mjs
 * pattern — upstream quirks live at the upstream boundary): the heic/heif
 * the gate admits for Vertex would 400 here. Such an image SKIPS the
 * candidate (OpenRouter serves it) rather than burning an attempt.
 * Deliberately NO wider than the gate either: OpenAI also takes gif, but the
 * shared gate never admits it (Anthropic Coverage design — zero observed
 * volume), so listing it here would be unreachable and would misstate what
 * this path serves (CodeRabbit #165). Probed 2026-09-10: png and webp → 200
 * on every seeded model, counted as ordinary input tokens. Mirror of hp
 * bedrockChatTranslator.ts.
 */
const BEDROCK_IMAGE_DATA_URI_RE = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/;

/** Chat message content (string | text-part array) → plain text, or null on shapes we didn't clear. */
function contentToText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const parts = [];
    for (const part of content) {
      // Text only on this path (assistant echoes and tool outputs) — an
      // image anywhere but a user turn is a shape we did not clear.
      if (part?.type !== 'text' || typeof part.text !== 'string') return null;
      parts.push(part.text);
    }
    return parts.join('');
  }
  if (content === null || content === undefined) return '';
  return null;
}

/**
 * USER-turn content → Responses input items (`input_text` / `input_image`),
 * or null on shapes we didn't clear. Adjacent text parts join into one item,
 * exactly as contentToText did before images were admitted, so a text-only
 * turn projects byte-identically to the pre-image translation. Empty text is
 * dropped; a turn whose parts are all empty yields [].
 */
function userContentToItems(content) {
  if (typeof content === 'string') return content === '' ? [] : [{ type: 'input_text', text: content }];
  if (!Array.isArray(content)) return content === null || content === undefined ? [] : null;
  const items = [];
  let text = '';
  const flushText = () => {
    if (text !== '') items.push({ type: 'input_text', text });
    text = '';
  };
  for (const part of content) {
    if (part?.type === 'text' && typeof part.text === 'string') {
      text += part.text;
      continue;
    }
    if (part?.type === 'image_url' && typeof part?.image_url?.url === 'string') {
      // The gate admitted this as a canonical-base64 data URI within its
      // shared media set and size caps; narrow to what mantle takes.
      if (!BEDROCK_IMAGE_DATA_URI_RE.test(part.image_url.url)) return null;
      flushText();
      // `detail` stays at the API default — the chat part's optional hint is
      // not forwarded (OpenRouter does not document honoring it either).
      items.push({ type: 'input_image', image_url: part.image_url.url });
      continue;
    }
    // Anything else is a shape we did not clear — refuse the candidate.
    return null;
  }
  flushText();
  return items;
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
  // Streaming and non-streaming both ride this wire (horse-power #1159): a
  // streaming client gets the Responses SSE translated frame by frame
  // (ResponsesToChatSse); a non-streaming one gets the single Responses
  // object translated to one chat.completion (ResponsesJsonToChat).
  const streaming = projected.stream === true;

  const source = Array.isArray(projected.messages) ? projected.messages : [];
  const input = [];
  for (const message of source) {
    const role = message?.role;
    if (role === 'user') {
      // The one turn that may carry images (the gate admits them on user
      // turns only, on image-capable candidates of providers in
      // IMAGE_DIRECT_PROVIDERS).
      const items = userContentToItems(message.content);
      if (items === null) return skip('bedrock_unmappable_field', 'messages.content');
      if (items.length > 0) input.push({ role, content: items });
      continue;
    }
    if (role === 'system' || role === 'developer' || role === 'assistant') {
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
    stream: streaming,
    // PRIVACY: the Responses API persists responses by default (`store`
    // defaults true). This proxy exists so content never rests outside the
    // enclave — always opt out.
    store: false,
  };

  const maxTokens = projected.max_completion_tokens ?? projected.max_tokens;
  if (typeof maxTokens === 'number') body.max_output_tokens = maxTokens;
  // temperature / top_p: deliberately NOT forwarded — see BEDROCK_MAPPABLE_FIELDS.
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
  if (projected.verbosity !== undefined) {
    body.text = { verbosity: projected.verbosity };
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

  const responses = responsesBodyFor(candidate, basePayload);
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
        accept: JSON.parse(bodyStr).stream === true ? 'text/event-stream' : 'application/json',
        'content-length': Buffer.byteLength(bodyStr),
        ...signed,
      },
    },
  };
}

/**
 * The shared half of both Responses-wire builders: the SHARED eligibility
 * gate, the allowed-field projection and the chat→Responses translation.
 * Returns `{ bodyStr }` or a skip. Transport-agnostic — who signs or bears
 * what is the caller's business.
 */
function responsesBodyFor(candidate, basePayload) {
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
  // A `-pro` row (OpenAI, horse-power #1156): the base model with the row's
  // reasoning mode. From the ROW, never the payload (the gate bails a caller's
  // reasoning.mode); bedrock candidates never carry one.
  if (row.reasoningMode) {
    responses.body.reasoning = { ...(responses.body.reasoning ?? {}), mode: row.reasoningMode };
  }

  return { body: responses.body };
}

/**
 * Build the outbound Responses API request for an OpenAI first-party
 * candidate (horse-power #1156), or a skip reason — buildBedrockRequest minus
 * SigV4: the same translation to the same wire grammar, posted to
 * api.openai.com with `Authorization: Bearer <key>` (key_ref 'openai', our
 * Infron.ai reseller project key — the key OpenRouter already calls OpenAI
 * with for us as BYOK). apiStyle 'openai-responses' selects the same
 * Responses→chat translator on the way back.
 *
 * Why the Responses wire and not OpenAI's chat endpoint (which exists): the
 * reasoning models refuse function tools there whenever reasoning is in play
 * ("use /v1/responses" — probed 2026-10-27 on gpt-6-astra and gpt-5.5) and
 * refuse temperature/top_p/stop/penalties/logprobs/max_tokens outright. This
 * translation already drops the first two and skips the rest.
 *
 * @param ports host -> local vsock tunnel port
 * @param keys  key_ref -> provisioned upstream API key
 */
export function buildOpenAIResponsesRequest({ candidate, basePayload, ports, keys, creditId, safetySecret }) {
  const port = ports?.[candidate.host];
  const key = keys?.[candidate.key_ref];
  if (!port || !key) return skip('no_tunnel_or_key');

  const responses = responsesBodyFor(candidate, basePayload);
  if (responses.skip) return responses;

  // Per-end-user attribution, as on the OpenRouter path (routing.mjs
  // applySafetyIdentifier stamps `user` = HMAC(credit_id) there, after the
  // direct clone was taken, so the clone carries none). The translator drops
  // the chat `user`; on the Responses API the parameter is
  // `safety_identifier`. Always OURS — a caller-supplied value never reaches
  // the wire — and a no-op without the secret, exactly like the OpenRouter
  // side (CodeRabbit on #386). Set here rather than in the shared translation
  // because mantle has no equivalent field.
  const identifier = computeSafetyIdentifier(creditId, safetySecret);
  if (identifier !== null) responses.body.safety_identifier = identifier;

  const bodyStr = JSON.stringify(responses.body);
  return {
    provider: candidate.provider,
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
    apiStyle: 'openai-responses',
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
        accept: JSON.parse(bodyStr).stream === true ? 'text/event-stream' : 'application/json',
        'content-length': Buffer.byteLength(bodyStr),
        authorization: `Bearer ${key}`,
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
    // response.created's echo of the model that actually serves: the ONE
    // served_model the receipt is signed with and the settle reports (see
    // MessagesToChatSse.wireModel). If the terminal event names a different
    // model it is kept apart as terminalModel and the settle records the
    // disagreement instead of silently preferring either.
    this.wireModel = null;
    this.terminalModel = null;
    this.id = `chatcmpl-${randomBytes(8).toString('hex')}`;
    this.created = Math.floor(Date.now() / 1000);
    this.buffer = '';
    this.eventData = [];
    this.toolIndexByItem = new Map();
    this.argsSentByIndex = new Map();
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

  /** Emit the portion of a terminal arguments string the deltas never carried. */
  _emitArgsSuffix(index, full) {
    const sent = this.argsSentByIndex.get(index) ?? '';
    if (full.length <= sent.length || !full.startsWith(sent)) return '';
    this.argsSentByIndex.set(index, full);
    return this._chunk({
      tool_calls: [{ index, function: { arguments: full.slice(sent.length) } }],
    });
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
        if (typeof event.response?.model === 'string') this.wireModel = event.response.model;
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
        this.argsSentByIndex.set(index, (this.argsSentByIndex.get(index) ?? '') + event.delta);
        return this._chunk({
          tool_calls: [{ index, function: { arguments: event.delta } }],
        });
      }

      // The terminal argument shapes repeat the COMPLETE arguments string.
      // Defensive backfill (parity with hp's bedrockChatTranslator.ts, hp
      // PR #867): if the deltas never arrived (or under-delivered), emit only
      // the missing suffix; if they delivered everything, this is a no-op. A
      // terminal string that contradicts the streamed prefix is dropped —
      // never corrupt what the client already received. Live-probed
      // 2026-09-02: mantle DOES stream deltas, so this is belt-and-braces.
      case 'response.function_call_arguments.done': {
        const index =
          this.toolIndexByItem.get(event.item_id) ?? this.toolIndexByItem.get(event.output_index);
        if (index === undefined || typeof event.arguments !== 'string') return '';
        return this._emitArgsSuffix(index, event.arguments);
      }

      case 'response.output_item.done': {
        const item = event.item;
        if (item?.type !== 'function_call' || typeof item.arguments !== 'string') return '';
        const index = this.toolIndexByItem.get(item.id ?? event.output_index);
        if (index === undefined) return '';
        return this._emitArgsSuffix(index, item.arguments);
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
        if (typeof response?.model === 'string') this.terminalModel = response.model;

        // Usage frame: pass Bedrock's numbers through VERBATIM — the subset
        // convention (both cache buckets ⊆ input_tokens) is exactly what
        // cost.mjs parses and hp's settle path prices (write premium incl.).
        const usage = response.usage;
        if (usage) {
          const frame = {
            id: this.id,
            object: 'chat.completion.chunk',
            created: this.created,
            model: typeof response.model === 'string' ? response.model : (this.wireModel ?? this.model),
            choices: [],
            // Under the CHAT names (horse-power #1159; previously the Responses
            // names leaked through): an SDK reading usage off the stream
            // finds prompt_tokens / completion_tokens as on every other
            // route. The subset convention is unchanged — cost.mjs reads
            // either spelling, and hp's settle prices the same numbers.
            usage: {
              prompt_tokens: Number(usage.input_tokens ?? 0),
              completion_tokens: Number(usage.output_tokens ?? 0),
              total_tokens: Number(usage.input_tokens ?? 0) + Number(usage.output_tokens ?? 0),
              prompt_tokens_details: {
                cached_tokens: Number(usage.input_tokens_details?.cached_tokens ?? 0),
                cache_write_tokens: Number(usage.input_tokens_details?.cache_write_tokens ?? 0),
              },
              ...(usage.output_tokens_details?.reasoning_tokens !== undefined
                ? { completion_tokens_details: { reasoning_tokens: Number(usage.output_tokens_details.reasoning_tokens ?? 0) } }
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

/**
 * The most a non-streaming Responses body may weigh before it is refused
 * rather than buffered (responsesMessages.mjs MAX_PENDING_CHARS).
 */
export const MAX_JSON_BODY_BYTES = 4 * 1024 * 1024;

/**
 * One NON-streaming Responses object → one chat.completion (horse-power
 * #1159). The same mapping ResponsesToChatSse applies frame by frame,
 * collapsed: output_text parts join into `message.content`, function_call
 * items become `tool_calls`, a refusal part rides `message.refusal`,
 * `status` / `incomplete_details` pick the finish reason, usage keeps the
 * subset convention under the chat names. `model` is the WIRE echo, as on the
 * streaming usage frame: the receipt and the settle read it, the rewriter
 * maps it to the public slug for the client. An `error` member, a `failed`
 * status or a non-object body become the `{"error":{…}}` envelope. Mirror of
 * hp bedrockChatTranslator.ts responsesJsonToChatCompletion.
 */
export function responsesJsonToChatCompletion(response, { upstreamModel }) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    return { error: { message: 'upstream response was not a Responses object', code: 502 } };
  }
  if (response.error && typeof response.error === 'object') {
    return { error: { message: `upstream ${response.error.message || 'response failed'}`, code: 502 } };
  }
  if (response.status === 'failed') {
    return { error: { message: 'upstream response failed', code: 502 } };
  }
  let content = '';
  let refusal = '';
  const toolCalls = [];
  for (const item of Array.isArray(response.output) ? response.output : []) {
    if (item?.type === 'message' && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part?.type === 'output_text' && typeof part.text === 'string') content += part.text;
        else if (part?.type === 'refusal' && typeof part.refusal === 'string') refusal += part.refusal;
      }
    } else if (item?.type === 'function_call') {
      toolCalls.push({
        id: String(item.call_id ?? item.id ?? ''),
        type: 'function',
        function: { name: typeof item.name === 'string' ? item.name : '', arguments: typeof item.arguments === 'string' ? item.arguments : '' },
      });
    }
  }
  const reason = response.status === 'incomplete' ? response.incomplete_details?.reason : undefined;
  const finishReason =
    reason === 'max_output_tokens' ? 'length' : reason === 'content_filter' ? 'content_filter' : toolCalls.length > 0 ? 'tool_calls' : 'stop';
  const usage = response.usage ?? {};
  const inputTokens = Number(usage.input_tokens ?? 0);
  const outputTokens = Number(usage.output_tokens ?? 0);
  const details = usage.input_tokens_details ?? {};
  const message = { role: 'assistant', content: content === '' ? null : content };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;
  if (refusal !== '') message.refusal = refusal;
  return {
    id: `chatcmpl-${randomBytes(8).toString('hex')}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: typeof response.model === 'string' && response.model !== '' ? response.model : upstreamModel,
    choices: [{ index: 0, message, finish_reason: finishReason }],
    usage: {
      prompt_tokens: inputTokens,
      completion_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
      prompt_tokens_details: {
        cached_tokens: Number(details.cached_tokens ?? 0),
        cache_write_tokens: Number(details.cache_write_tokens ?? 0),
      },
      ...(usage.output_tokens_details?.reasoning_tokens !== undefined
        ? { completion_tokens_details: { reasoning_tokens: Number(usage.output_tokens_details.reasoning_tokens ?? 0) } }
        : {}),
    },
  };
}

/**
 * The non-streaming twin of ResponsesToChatSse: the same feed()/finish()
 * contract the relay drives, buffering the one Responses object (bounded)
 * and emitting the chat.completion on finish(). `wireModel` is set from the
 * object for the receipt/settle (servedModelReport); `contentType` tells the
 * relay what the client is getting.
 */
export class ResponsesJsonToChat {
  constructor({ upstreamModel }) {
    this.model = upstreamModel;
    this.contentType = 'application/json';
    this.streaming = false;
    this.wireModel = null;
    this.terminalModel = null;
    this.chunks = [];
    this.bytes = 0;
    this.over = false;
    this.done = false;
  }
  feed(chunk) {
    if (this.done || this.over) return Buffer.alloc(0);
    this.bytes += chunk.length;
    if (this.bytes > MAX_JSON_BODY_BYTES) {
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
      out = { error: { message: 'upstream response body over the size cap', code: 502 } };
    } else {
      let parsed;
      try {
        parsed = JSON.parse(Buffer.concat(this.chunks).toString('utf8'));
      } catch {
        parsed = undefined;
      }
      out =
        parsed === undefined
          ? { error: { message: 'upstream response body was not JSON', code: 502 } }
          : responsesJsonToChatCompletion(parsed, { upstreamModel: this.model });
      if (parsed && typeof parsed.model === 'string') this.wireModel = parsed.model;
    }
    this.chunks = [];
    return Buffer.from(JSON.stringify(out), 'utf8');
  }
}
