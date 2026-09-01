/**
 * Direct-provider eligibility gate — a faithful port of horse-power
 * services/directProviders/eligibility.ts.
 *
 * WHY THIS LIVES IN THE ENCLAVE (unlike the rest of the direct-provider
 * subsystem, which stays in hp): the decision depends on the DECRYPTED request
 * body (top-level fields, per-message fields, content shape) that hp never sees.
 * So the *catalog/policy* stays in hp (it builds the upstream candidate list at
 * /authorize) and this *content* gate runs here on the plaintext payload.
 *
 * PURE by design: no env, no fetch, no logging, and it never mutates the payload.
 * Allowlist, not denylist: an unknown field bails to OpenRouter (the safe
 * status quo) rather than 422-ing a direct provider. A failed/ineligible direct
 * attempt always falls back to OpenRouter, so being wrong here is at worst a
 * missed optimization, never a hard failure.
 *
 * DRIFT HAZARD: keep behaviourally identical to eligibility.ts (guarded by hp's
 * conformance test). isFree + isRowEnabled are inlined (hp imports them).
 */

/** hp models.service.ts isFree — exact-slug list. */
export function isFree(model) {
  return model === 'ppq/free' || model === 'openrouter/free';
}

/**
 * True when a free alias reached us WITHOUT hp's `is_free` directive, in which
 * case the enclave must refuse instead of serving it on the paid path.
 *
 * hp initialises `resolved_model = model` and overwrites it only on success, so
 * a resolution failure returns the raw slug alongside `is_free: false` — and the
 * enclave cannot tell that apart from a successful resolution, since both are
 * non-empty strings. `openrouter/free` is a real OpenRouter slug, so such a
 * request WOULD be served, with no applyFreeModelStrip: any `web` plugin the
 * caller attached survives and PPQ buys it on a request that must cost $0.
 *
 * Pure so it can be tested without standing up the server; the caller turns a
 * true into a 400, which sends the client back to the normal path.
 */
export function refusesUnauthorizedFree(model, authIsFree) {
  return isFree(model) && authIsFree !== true;
}
/** hp directProviders/types.ts isRowEnabled — admin override wins. */
function isRowEnabled(row) {
  return row.enabledOverride ?? row.enabled;
}

// Fields copied verbatim into the direct-provider request body (OpenAI dialect).
// Deliberately absent: OpenRouter's `reasoning` object + `usage`.
export const ALLOWED_FIELDS = new Set([
  'model',
  'messages',
  'stream',
  'stream_options',
  'temperature',
  'top_p',
  'top_k',
  'min_p',
  'max_tokens',
  'max_completion_tokens',
  'stop',
  'n',
  'seed',
  'frequency_penalty',
  'presence_penalty',
  'repetition_penalty',
  'logprobs',
  'top_logprobs',
  'logit_bias',
  'response_format',
  'tools',
  'tool_choice',
  'parallel_tool_calls',
  'reasoning_effort',
  'user',
]);

// Fields copied verbatim on the Anthropic `/messages` dialect (Phase 2 upstreams).
export const ALLOWED_MESSAGES_FIELDS = new Set([
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
]);

// PPQ-internal / already-consumed fields: not forwarded, but NOT a bail reason.
export const IGNORED_FIELDS = new Set([
  'query_source',
  'session_id',
  'chat_id',
  'tool_id',
  'zdr',
  'search_mode',
  'credit_id',
  'api_key',
  // PPQ-internal, never forwarded upstream. `plugins` rides on EVERY chat
  // request from the web app (it arrives as [] when no search was asked for)
  // and `data_source` is vestigial on this path — between them they
  // disqualified 100% of UI traffic from the direct providers. Ignoring
  // `plugins` is safe because requestsWebSearch() runs BEFORE the allowlist
  // sweep, so a `web` plugin still forces the OpenRouter fallback.
  'plugins',
  'data_source',
]);

// Keys permitted on each chat-completions messages[] entry. `reasoning_content`
// is allowed (Fireworks accepts it, prefix-caches on it); `reasoning` is not.
export const ALLOWED_MESSAGE_FIELDS = new Set([
  'role',
  'content',
  'name',
  'tool_calls',
  'tool_call_id',
  'reasoning_content',
]);

// Keys permitted on a `/messages` messages[] entry (Anthropic shape: role + content).
export const ALLOWED_MESSAGES_MESSAGE_FIELDS = new Set(['role', 'content']);

const ELIGIBLE = { eligible: true };

function bail(reason, offendingField) {
  return offendingField ? { eligible: false, reason, offendingField } : { eligible: false, reason };
}

/** Models with PPQ-specific routing semantics that only OpenRouter can serve. */
function isRouterModel(model) {
  return model === 'openrouter/auto' || model === 'auto' || model.startsWith('autorouter/');
}

/**
 * True when the request asks for web search in either encoding OpenRouter accepts:
 * the `web` plugin, or the `openrouter:web_search` server tool. Both are executed
 * by OpenRouter only; a direct provider silently ignores them, so a web-search
 * request must route to OpenRouter. Pure — inspects only plugins/tools shape.
 */
function requestsWebSearch(payload) {
  const plugins = payload?.plugins;
  if (Array.isArray(plugins) && plugins.some((p) => p?.id === 'web')) return true;
  const tools = payload?.tools;
  // BOTH wire forms: `web_search` is PPQ's provider-neutral public tool type
  // (frontend #2524) and is what the app emits for Auto mode today;
  // `openrouter:web_search` is the legacy shape still in stored conversations.
  // Matching only the legacy one let every Auto-mode search through to a direct
  // provider, which drops the tool and answers with no results and NO error.
  if (
    Array.isArray(tools) &&
    tools.some((t) => t?.type === 'web_search' || t?.type === 'openrouter:web_search')
  ) {
    return true;
  }
  return false;
}

// Ceilings for image data URIs, in characters (≈ bytes for base64 ASCII):
// per image, and for the SUM across the payload — the aggregate is what
// actually protects Vertex's 20MB request ceiling (three individually-valid
// 7MB images would sail past a per-image check and fail upstream). Kept
// identical to horse-power services/directProviders/eligibility.ts.
const MAX_IMAGE_DATA_URI_CHARS = 7 * 1024 * 1024;
const MAX_TOTAL_IMAGE_DATA_URI_CHARS = 14 * 1024 * 1024;

// Media types cleared for the direct path — Gemini's documented image input
// set. A data URI outside it (URL-encoded svg markup, say) or without the
// `;base64,` marker would 400 upstream for client input. Probe-pending like
// every launch allowlist; kept identical to hp.
const IMAGE_DATA_URI_PREFIX_RE = /^data:image\/(png|jpeg|webp|heic|heif);base64,/;

/**
 * An `image_url` part the direct path may carry: a base64 `data:image/…` URI
 * of a cleared media type, within the per-image ceiling. DELIBERATELY not
 * https URLs — OpenRouter fetches and inlines remote images itself, and the
 * enclave must not grow an image fetcher; remote-URL image requests fall
 * through to the OpenRouter candidate.
 */
function isDataImagePart(part) {
  const url = part?.image_url?.url;
  return (
    part?.type === 'image_url' &&
    typeof url === 'string' &&
    IMAGE_DATA_URI_PREFIX_RE.test(url) &&
    url.length <= MAX_IMAGE_DATA_URI_CHARS
  );
}

/** Sum of image data-URI chars in one message's content (0 for non-arrays). */
function imageDataUriChars(content) {
  if (!Array.isArray(content)) return 0;
  let total = 0;
  for (const part of content) {
    if (part?.type === 'image_url' && typeof part?.image_url?.url === 'string') {
      total += part.image_url.url.length;
    }
  }
  return total;
}

/**
 * True when message content is expressible on the direct path: text always;
 * data-URI image parts only when `allowImages` (derived from
 * IMAGE_DIRECT_PROVIDERS + the candidate's supports_image_input + the
 * message role — see the message loop).
 */
function isSupportedChatContent(content, allowImages) {
  if (typeof content === 'string') return true;
  if (Array.isArray(content)) {
    return content.every(
      (part) =>
        (part?.type === 'text' && typeof part.text === 'string') ||
        (allowImages && isDataImagePart(part)),
    );
  }
  // null/absent content is valid for assistant tool-call turns.
  return content === null || content === undefined;
}

/** One Anthropic content block, validated by its type discriminator. */
function isSupportedAnthropicBlock(block) {
  if (!block || typeof block !== 'object') return false;
  switch (block.type) {
    case 'text':
      return typeof block.text === 'string';
    case 'thinking':
      return typeof block.thinking === 'string';
    case 'redacted_thinking':
      return typeof block.data === 'string';
    case 'tool_use':
      return typeof block.id === 'string' && typeof block.name === 'string';
    case 'tool_result':
      return (
        block.content === undefined ||
        typeof block.content === 'string' ||
        (Array.isArray(block.content) &&
          block.content.every((b) => b?.type === 'text' && typeof b.text === 'string'))
      );
    default:
      return false;
  }
}

/** True when `/messages` content is within the supported Anthropic block vocabulary. */
function isSupportedAnthropicContent(content) {
  if (typeof content === 'string') return true;
  if (Array.isArray(content)) return content.length > 0 && content.every(isSupportedAnthropicBlock);
  return false;
}

/** The top-level `system` field: string, or an array of text blocks. */
function isSupportedAnthropicSystem(system) {
  if (system === undefined) return true;
  if (typeof system === 'string') return true;
  if (Array.isArray(system)) {
    return system.every((b) => b?.type === 'text' && typeof b.text === 'string');
  }
  return false;
}

/**
 * Direct providers whose inference endpoints are zero-data-retention, so a
 * `provider.zdr === true` request (the Private-models UI) may be served direct
 * instead of bailing to OpenRouter's ZDR endpoint routing. Default closed —
 * add a provider only with a documented retention guarantee. Keep in sync with
 * horse-power services/directProviders/types.ts ZDR_DIRECT_PROVIDERS.
 */
export const ZDR_DIRECT_PROVIDERS = new Set(['fireworks']);

/**
 * Direct providers whose adapters may be handed IMAGE input — data-URI
 * `image_url` parts. Default-closed like ZDR_DIRECT_PROVIDERS: a provider
 * absent here keeps bailing image content to the OpenRouter candidate, and
 * one may be added only after probing its image handling end-to-end. Keep in
 * sync with horse-power services/directProviders/types.ts
 * IMAGE_DIRECT_PROVIDERS.
 */
export const IMAGE_DIRECT_PROVIDERS = new Set(['vertex']);

/**
 * True when `provider` is exactly `{ zdr: true }` — the shape the
 * Private-models UI sends and the only provider object the direct path may
 * absorb. Key-count-exact: a provider object that ALSO carries routing
 * directives must keep bailing.
 */
function isZdrOnlyProviderObject(p) {
  return (
    !!p &&
    typeof p === 'object' &&
    !Array.isArray(p) &&
    p.zdr === true &&
    Object.keys(p).length === 1
  );
}

/** `json_schema` bails; `text`/`json_object`/absent pass. */
function isSupportedResponseFormat(rf) {
  if (rf === undefined) return true;
  if (!rf || typeof rf !== 'object') return false;
  const type = rf.type;
  return type === 'text' || type === 'json_object';
}

/**
 * Decide whether a chat request may go to a direct provider. `row` is the
 * catalog projection for payload.model (or undefined). Never mutates payload.
 */
export function evaluateDirectEligibility({ payload, path, modelSuffixes, row }) {
  if (path !== '/chat/completions' && path !== '/messages') {
    return bail('endpoint_not_chat_completions');
  }
  const isMessagesDialect = path === '/messages';
  const allowedFields = isMessagesDialect ? ALLOWED_MESSAGES_FIELDS : ALLOWED_FIELDS;

  if (typeof payload?.model !== 'string' || payload.model.length === 0) {
    return bail('model_not_in_catalog');
  }
  if (isFree(payload.model)) {
    return bail('free_model');
  }
  if (isRouterModel(payload.model)) {
    return bail('auto_router_model');
  }
  if (Array.isArray(modelSuffixes) && modelSuffixes.length > 0) {
    return bail('or_routing_suffix');
  }
  // A ZDR request may go direct only when the candidate row's provider is
  // itself zero-data-retention (Fireworks qualifies); any other provider
  // bails so OpenRouter's router enforces ZDR endpoint selection. Keep
  // byte-in-sync with horse-power eligibility.ts (conformance test).
  if (payload.provider?.zdr === true && (!row || !ZDR_DIRECT_PROVIDERS.has(row.provider))) {
    return bail('zdr_requested');
  }

  // Web search is OpenRouter-native: only OpenRouter executes the `web` plugin
  // and the `openrouter:web_search` server tool. A direct provider (Fireworks)
  // silently drops the tool and answers with NO search results. The plugin form
  // bails via the allowlist sweep below, but the SERVER-TOOL form does not
  // (`tools` is allowlisted; the tools bail fires only when the row lacks tool
  // support) — so a web_search tool on a tool-capable model would reach Fireworks
  // and lose the search. Force OpenRouter for either encoding. Keep byte-in-sync
  // with horse-power services/directProviders/eligibility.ts (conformance test).
  if (requestsWebSearch(payload)) {
    return bail('web_search_requires_openrouter');
  }

  // Allowlist sweep — unknown/OpenRouter-specific keys bail.
  for (const key of Object.keys(payload)) {
    if (allowedFields.has(key) || IGNORED_FIELDS.has(key)) continue;
    if (payload[key] === undefined) continue;
    // A `provider` carrying ONLY `{zdr: true}` is a privacy request the direct
    // path satisfies by construction (the ZDR check above verified the row's
    // provider); it is never forwarded (`provider` is not allowlisted). Any
    // OTHER provider content is an OpenRouter routing directive and still
    // bails — including alongside zdr.
    if (key === 'provider' && isZdrOnlyProviderObject(payload.provider)) continue;
    return bail('unsupported_field', key);
  }

  if (!Array.isArray(payload.messages) || payload.messages.length === 0) {
    return bail('malformed_messages');
  }
  let totalImageDataUriChars = 0;
  for (const message of payload.messages) {
    if (!message || typeof message !== 'object') return bail('malformed_messages');
    const allowedMessageFields = isMessagesDialect
      ? ALLOWED_MESSAGES_MESSAGE_FIELDS
      : ALLOWED_MESSAGE_FIELDS;
    for (const key of Object.keys(message)) {
      if (!allowedMessageFields.has(key)) {
        return bail('unsupported_message_field', key);
      }
    }
    if (isMessagesDialect) {
      if (!isSupportedAnthropicContent(message.content)) return bail('non_text_content');
    } else {
      // Image admission peeks at the row (same documented exception as the
      // ZDR check): only a provider in IMAGE_DIRECT_PROVIDERS whose candidate
      // advertises image support may be handed data-URI image parts, and only
      // in USER turns. Kept in behavioral lockstep with horse-power's gate
      // (the hp conformance suite compares the two).
      const allowImages =
        message.role === 'user' &&
        row !== undefined &&
        row.supportsImageInput === true &&
        IMAGE_DIRECT_PROVIDERS.has(row.provider);
      if (!isSupportedChatContent(message.content, allowImages)) return bail('non_text_content');
      // Aggregate cap across the whole payload: each image passed the
      // per-image ceiling above, but their SUM is what the provider's
      // request limit actually constrains.
      totalImageDataUriChars += imageDataUriChars(message.content);
      if (totalImageDataUriChars > MAX_TOTAL_IMAGE_DATA_URI_CHARS) {
        return bail('non_text_content');
      }
    }
  }

  if (isMessagesDialect && !isSupportedAnthropicSystem(payload.system)) {
    return bail('non_text_content');
  }

  if (!isSupportedResponseFormat(payload.response_format)) {
    return bail('response_format_unsupported');
  }

  if (!row) {
    return bail('model_not_in_catalog');
  }
  if (!isRowEnabled(row)) {
    return bail('model_disabled');
  }
  if (Array.isArray(payload.tools) && payload.tools.length > 0 && row.supportsTools !== true) {
    return bail('tools_unsupported_by_model');
  }

  return ELIGIBLE;
}

/**
 * Build the upstream request body: a fresh object with ONLY allowlisted fields.
 * Never mutates payload. `model` comes from the row (the security invariant: wire
 * identity + billing rate from the same document).
 */
export function projectAllowedFields(payload, row, path = '/chat/completions') {
  const allowedFields = path === '/messages' ? ALLOWED_MESSAGES_FIELDS : ALLOWED_FIELDS;
  const body = {};
  for (const key of Object.keys(payload)) {
    if (!allowedFields.has(key)) continue;
    if (payload[key] === undefined) continue;
    body[key] = payload[key];
  }

  body.model = row.upstreamModelId;
  if (row.serviceTier) {
    body.service_tier = row.serviceTier;
  }

  // Token counts are the ONLY cost input on the direct path, so pin usage on.
  // stream_options is an OpenAI-ism the /messages surface 400s on.
  if (path !== '/messages') {
    if (payload.stream === true) {
      body.stream_options = { ...(payload.stream_options ?? {}), include_usage: true };
    } else {
      delete body.stream_options;
    }
  }

  return body;
}
