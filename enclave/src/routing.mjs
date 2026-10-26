/**
 * Model resolution + payload transforms.
 *
 * A trimmed, dependency-free port of horse-power's services/chatPayload.ts.
 * These operate on decrypted content, so they MUST run inside the enclave.
 *
 * Scope: provider-routing transforms + usage.include. AutoClaw/AutoRouter
 * smart routing lives in smartRouting.mjs (a port of ClawRouter's rules
 * classifier only; hp sends the tier tables per request).
 */

import { createHmac } from 'node:crypto';
import {
  applyWebSearchEngine,
  hasWebSearch,
  swapWebPluginForServerTool,
  swapWebSearchToolForPlugin,
  webPluginBreaksModel, isActiveWebPlugin, isActivePlugin,
  webSearchToolActive as webSearchToolCallable,
} from './webSearchTransforms.mjs';

/** The engine label the settle reports when OpenRouter's Exa plugin ran. */
export const WEB_SEARCH_ENGINE_EXA = 'exa';

/**
 * Whether an outbound OpenRouter payload, AFTER transformPayload and the
 * strips, runs the Exa plugin: a `web` plugin whose engine is `exa`. A mirror
 * of horse-power's services/webSearchFee.ts exaWebPluginRequested, kept
 * byte-for-byte in logic so the two sides judge one payload the same way.
 * Read from the payload that is actually sent, never from the caller's
 * request: applyWebSearchEngine sets the engine (and leaves Perplexity's
 * unset), and the #676 / #2550 swaps decide whether a plugin is sent at all.
 */
export function exaWebPluginRequested(payload) {
  const plugins = payload?.plugins;
  if (!Array.isArray(plugins)) return false;
  // `enabled: false` is OpenRouter's documented way to turn the plugin OFF for
  // the request (webSearchTransforms.mjs isActiveWebPlugin): no search ran, so
  // no engine, and no fee for horse-power to add (horse-power #1094).
  return plugins.some(
    (p) => p && typeof p === 'object' && isActiveWebPlugin(p) && p.engine === WEB_SEARCH_ENGINE_EXA,
  );
}

/**
 * Which engine the web search on an outbound body runs on, for the settle's
 * `web_search_engine` (horse-power #1088; Oct 17-19 security reports, hel's
 * paid-fee finding, Matt's item 9):
 *
 *   'exa'    the `web` plugin with engine `exa`: OpenRouter runs Exa before
 *            inference and bills it outside a BYOK provider's inference cost,
 *            so a BYOK row's settled cost excludes it and hp adds the
 *            published fee;
 *   'native' any other search the body asks for (the `openrouter:web_search`
 *            server tool, Anthropic's dated tool, OpenAI's web_search_preview,
 *            Perplexity's engine-less plugin): the PROVIDER runs and bills it,
 *            inside its inference cost, so no fee applies;
 *   undefined when the body asks for no search at all (a free model after the
 *            strip, or a request that never asked).
 *
 * `hasSearch` is the dialect's own "asks for search" test (the chat path's
 * hasWebSearch, or a dialect descriptor's hasWebSearch), judged on the SAME
 * final body, so this never says 'native' for a request the settle reports
 * as offline.
 */
export function webSearchEngineOf(payload, hasSearch = hasWebSearch) {
  if (exaWebPluginRequested(payload)) return WEB_SEARCH_ENGINE_EXA;
  return hasSearch(payload) ? 'native' : undefined;
}

export function resolveModel(payload) {
  if (payload.model && typeof payload.model === 'object' && payload.model.id) {
    payload.model = payload.model.id;
  }
  if (typeof payload.model !== 'string') {
    throw new Error('Invalid payload: model must be a string');
  }
  // autoclaw/* and autorouter/* pass: hp answers /authorize with the tier
  // tables and smartRouting.mjs picks the model after authorization. An hp
  // that sends no directive still gets the 400 (server.mjs).
  // private/* (Tinfoil) models are served here since #210: hp's /authorize
  // answers with a single `tinfoil` candidate and the connector seals the body
  // to the router's attested key (tinfoil.mjs). They used to be refused with
  // "use the Tinfoil path"; that code (model_rejected_private_path) stays in
  // the vocabulary for hp's sake but is no longer produced.
}

/**
 * DRIFT HAZARD: keep in sync with horse-power services/chatPayload.ts
 * transformPayload. Only model-string-based provider routing is ported (needs
 * no catalog). Two catalog-/policy-dependent transforms — tool-support
 * stripping and free-model stripping — are decided by horse-power at /authorize
 * and applied post-transform via applyToolStrip / applyFreeModelStrip below
 * (issue #6); short-slug alias resolution is likewise resolved by hp (#2). Keep
 * the ported branches identical to the source.
 */
export function transformPayload(payload) {
  if (typeof payload.model !== 'string') {
    throw new Error('Invalid payload: model must be a string');
  }

  // A caller may pass OpenRouter's native `provider.zdr` to force Zero Data
  // Retention. The routing rules below own the rest of the `provider` object
  // (every `anthropic/*` branch REPLACES it), so capture just the ZDR
  // preference here and re-apply it after routing is set, never letting other
  // caller-supplied provider keys survive our overrides. Until the Oct 17-19
  // security reports (apienz, report 3/3) this port captured nothing: a
  // `provider: { zdr: true }` on a Claude model reached OpenRouter without the
  // flag, free to land on a non-ZDR endpoint, while hp's chatPayload.ts has
  // re-applied `callerZdr` since its ZDR work. Byte-parity port of that
  // capture (hp reads it after its web-search swaps; nothing between here and
  // there touches `provider.zdr`, so the read is equivalent).
  const callerZdr = payload.provider?.zdr === true;
  // Opus 4.8 + web search is the one combo where ZDR can't be honoured (see
  // the anthropic block); decided there, consumed by the re-apply below.
  let opus48Web = false;

  // Synthetic API-only fast string for GLM 5.2 — rewrite to the real slug and
  // pin Fireworks Fast (billing then treats it as the normal model).
  if (payload.model === 'z-ai/glm-5.2-fast' || payload.model === 'glm-5.2-fast') {
    payload.model = 'z-ai/glm-5.2';
    payload.provider = { order: ['fireworks/fast', 'fireworks'], allow_fallbacks: true };
  }

  if (payload.model.includes('anthropic')) {
    if (Array.isArray(payload.messages)) {
      addCachePromptMarks(payload.messages);
    }

    // #676: swap the web plugin for the server tool on Claude models it breaks,
    // BEFORE the provider reads below (which key off webPlugin/webSearchTool).
    if (webPluginBreaksModel(payload.model)) swapWebPluginForServerTool(payload);

    // Only plugins in effect count: a lone `{ id: 'web', enabled: false }` used
    // to move the request off the Bedrock BYOK pin for a search that never
    // runs. Keep in sync with horse-power chatPayload.ts `plugins` (hp #1095).
    const hasPlugins =
      Array.isArray(payload.plugins) && payload.plugins.some(isActivePlugin);
    const webPlugin =
      Array.isArray(payload.plugins) && payload.plugins.some(isActiveWebPlugin);
    // Callable, not merely declared: an `openrouter:web_search` tool under
    // `tool_choice: 'none'` (or a forced choice naming another tool) can never
    // search, so it must not move the request off the Bedrock BYOK pin. hp's
    // provider decision has read the callable predicate since #1096; the
    // by-type check this replaced routed the same request to OpenRouter credit
    // (found by the horse-power #1107 conformance fixtures). Keep in sync with
    // horse-power chatPayload.ts `webSearchToolActive`.
    const webSearchToolActive = webSearchToolCallable(payload);
    // Opus 5's usable Bedrock capacity is the `amazon-bedrock/claude-on-aws`
    // endpoint, which our AWS BYOK key does NOT cover — the pin below would
    // land there and burn OpenRouter credits (the #566 failure mode; the old
    // "flaky 502s" label was this same coverage gap). Opus 4.8 was removed
    // 2026-08-17 (stale premise; live-verified healthy on Bedrock). Keep in
    // sync with horse-power chatPayload.ts.
    const bedrockUnavailable = payload.model === 'anthropic/claude-opus-5';
    const isFable = payload.model.includes('fable');
    // Opus 4.8 + web search: a ZDR endpoint (Bedrock/Vertex) returns a
    // multi-turn `messages.N: role 'system' must follow...` 400 for Opus 4.8's
    // search-results layout, and the server tool is too flaky under ZDR to
    // rely on. Web search already sends the query to an external search
    // provider, so the caller's `zdr` is suppressed for this combo only, in
    // BOTH web-search forms (the `web` plugin and a callable
    // `openrouter:web_search` tool); the provider object itself is whatever
    // the branches below choose (today `ignore: ['amazon-bedrock']`, the same
    // as hp). Mirrors hp chatPayload.ts `opus48Web`; keep in sync.
    opus48Web =
      (webPlugin || webSearchToolActive) &&
      payload.model === 'anthropic/claude-opus-4.8';

    if (isFable) {
      payload.provider = { order: ['anthropic'], allow_fallbacks: false };
    } else if (webPlugin && bedrockUnavailable) {
      payload.provider = { order: ['anthropic'], allow_fallbacks: false };
    } else if (hasPlugins || webSearchToolActive || bedrockUnavailable) {
      payload.provider = { ignore: ['amazon-bedrock'] };
    } else {
      // DEFENSE (the #566 lesson): `order` matches EVERY variant under the
      // provider slug, including `claude-on-aws` — the one our AWS BYOK key
      // does not cover. The explicit ignore makes that trap impossible by
      // construction. Keep in sync with horse-power chatPayload.ts.
      payload.provider = {
        order: ['amazon-bedrock'],
        ignore: ['amazon-bedrock/claude-on-aws'],
        allow_fallbacks: false,
      };
    }

  }

  // (#hp1060) The gemini-2.5-flash Vertex exclusion (hp PR #405) is gone: every
  // google/gemini* model now arrives with hp's provider_directive
  // `{ only: ['google-vertex'], ... }` (GCP credits via our BYOK key), which the
  // Venice merge below preserves. Byte-parity port of hp chatPayload.ts, where
  // the pin lives in MODEL_OVERRIDES / overrideProviderDirective.
  if (
    !payload.model.includes('anthropic') &&
    !payload.model.startsWith(
      'cognitivecomputations/dolphin-mistral-24b-venice-edition',
    )
  ) {
    // Venice is excluded platform-wide. MERGE the exclusion into any provider
    // object the caller (or hp's provider_directive) supplied, rather than
    // setting it only when `provider` is absent: that `!payload.provider` guard
    // let any client-sent provider object (e.g. `{sort: 'price'}`) silently
    // drop the exclusion, and OpenRouter then prefers our Venice BYOK endpoint
    // (hp #997). Anthropic models set their own routing above and can't be
    // Venice-served. Byte-parity port of hp chatPayload.ts transformPayload.
    const existingIgnore = Array.isArray(payload.provider?.ignore)
      ? payload.provider.ignore
      : [];
    payload.provider = {
      ...(payload.provider ?? {}),
      ignore: existingIgnore.includes('venice')
        ? existingIgnore
        : [...existingIgnore, 'venice'],
    };
  }

  // Re-apply the caller's ZDR preference on top of our routing, except when it
  // would leave OpenRouter with no working endpoint (opus48Web, decided
  // above, needs a non-ZDR route). hp also skips a `forcePrivacy: 'anon'` model
  // override here; those never reach this port as a directive (hp sends only
  // `only` hard pins, all ZDR-capable), and no model carries one today.
  // Byte-parity port of hp chatPayload.ts; the dialect paths keep `zdr` in
  // applyHardProviderPin the same way.
  if (callerZdr && !opus48Web) {
    payload.provider = { ...(payload.provider ?? {}), zdr: true };
  }

  // NOTE: free-model plugin/tool stripping used to live here behind a local
  // `:free` heuristic that DRIFTED from hp's exact-slug isFree. It now runs as a
  // post-transform directive (applyFreeModelStrip, driven by hp's is_free) so
  // there is one source of truth. Tool-support stripping (applyToolStrip) is
  // likewise post-transform. Both must run AFTER this function (see server.mjs).

  // Issue PPQdotAI#2550: collapse the `openrouter:web_search` server tool to
  // the Exa `web` plugin on models with no provider-native search (the tool's
  // third-party-engine path costs a flat ~10s). Anthropic/Perplexity return
  // early inside — disjoint from the #676 swap above by construction. No
  // provider-routing read sits between here and those swaps in this port, so
  // ordering matches hp's transformPayload output exactly.
  swapWebSearchToolForPlugin(payload);

  // Standardize web search on the Exa engine (except Perplexity) — shared logic.
  applyWebSearchEngine(payload);

  // Always ask OpenRouter to include usage so we can bill from the stream.
  payload.usage = { ...(payload.usage || {}), include: true };
}

// Our injected breakpoints stop at 3, not Anthropic's 4: a caller that marks
// only a tool definition (pi's anthropic cache format) still fits under the
// 4-block limit with ours on top. Live-verified: tool-definition mark + 3 = 4
// serves; a 5th is a hard 400. Mirror of hp.
const MAX_INJECTED_CACHE_MARKS = 3;

// Anthropic rejects the entire request when cache_control sits on an empty
// text block ("cache_control cannot be set for empty text blocks" — #674), so
// only a block with real text can host a mark.
const isCacheableTextPart = (part) =>
  !!part && part.type === 'text' && typeof part.text === 'string' && part.text.trim() !== '';

// On the translated Messages dialect (anthropic.mjs) a tool result is a
// tool_result block inside a user turn — a legal cache_control host, with the
// same #674 rule applied to the text it carries.
const isCacheableToolResult = (part) =>
  !!part &&
  part.type === 'tool_result' &&
  (typeof part.content === 'string'
    ? part.content.trim() !== ''
    : Array.isArray(part.content) && part.content.some(isCacheableTextPart));

const blockHasCallerMark = (block) =>
  !!block &&
  (block.cache_control !== undefined ||
    (block.type === 'tool_result' &&
      Array.isArray(block.content) &&
      block.content.some((nested) => nested && nested.cache_control !== undefined)));

const hasCallerMark = (msg) =>
  !!msg &&
  (msg.cache_control !== undefined ||
    (Array.isArray(msg.content) && msg.content.some(blockHasCallerMark)));

const hasCacheableBlock = (msg) => {
  if (!msg) return false;
  if (typeof msg.content === 'string') return msg.content.trim() !== '';
  return (
    Array.isArray(msg.content) &&
    msg.content.some((part) => isCacheableTextPart(part) || isCacheableToolResult(part))
  );
};

// Mark the LAST block of the message that can legally carry a breakpoint.
// String content becomes a one-part array (the only way to carry a mark on
// the chat dialect); whitespace-only content is left alone and unmarked.
const markLastCacheableBlock = (msg) => {
  if (!hasCacheableBlock(msg)) return;
  if (typeof msg.content === 'string') {
    msg.content = [{ type: 'text', text: msg.content }];
  }
  const host = msg.content
    .filter((part) => isCacheableTextPart(part) || isCacheableToolResult(part))
    .pop();
  host.cache_control = { type: 'ephemeral' };
};

/**
 * Inject Anthropic ephemeral cache_control breakpoints for clients that do not
 * manage their own. Mirrors addCachePromptMarks in horse-power's
 * services/models.service.ts. Targets, deduped, capped at
 * MAX_INJECTED_CACHE_MARKS:
 *   1. messages[0] — the system prompt or first user turn: the stable prefix.
 *   2. the last two USER messages — the previous-turn anchors. This was the
 *      whole rule from Mar 2025 (Roo Code's addCacheBreakpoints, whose
 *      protocol carries tool results INSIDE user turns, so for it the last
 *      user message is the tail).
 *   3. the TAIL — the last message of ANY role with a cacheable block. On the
 *      OpenAI dialect an agent's newest content is a `role: 'tool'` result,
 *      not a user message: without this mark the breakpoint stayed on the
 *      user prompt and every tool round re-prefilled the whole loop at full
 *      price (hp #1116, Chatwoot 2125). On the translated Messages dialect
 *      tool results are user turns of tool_result blocks, so the same walk
 *      serves both paths.
 * Chat and Roo-style conversations end on a user message, so their marks are
 * exactly what they were; agent loops get messages[0] + the user prompt + the
 * last tool result. Over budget, the EARLIEST user anchor goes first.
 *
 * DRIFT HAZARD: keep in sync with models.service.ts addCachePromptMarks.
 */
export function addCachePromptMarks(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return;

  // GLOBAL check: if the caller already sent cache_control anywhere, respect it
  // and add none. Clients like Claude Code manage their own breakpoints, and
  // extra marks would exceed the provider's 4-block cache_control limit. A
  // mark nested inside a tool_result's content (native Messages-dialect
  // callers) counts the same as one on the message or on a top-level block.
  const hasExistingCacheControl = messages.some((msg) => hasCallerMark(msg));
  if (hasExistingCacheControl) return;

  const targets = [];
  const addTarget = (msg) => {
    if (msg && !targets.includes(msg)) targets.push(msg);
  };

  addTarget(messages[0]);
  for (const msg of messages.filter(({ role }) => role === 'user').slice(-2)) {
    addTarget(msg);
  }
  for (let i = messages.length - 1; i >= 0; i--) {
    if (hasCacheableBlock(messages[i])) {
      addTarget(messages[i]);
      break;
    }
  }
  // Over budget only when the tail is not a user message: drop the earliest
  // user anchor (index 1) — messages[0] and the tail earn the most.
  while (targets.length > MAX_INJECTED_CACHE_MARKS) targets.splice(1, 1);

  for (const msg of targets) markLastCacheableBlock(msg);
}

// ── OpenAI safety identifier (issue #657) ────────────────────────────────────
// Mirrors horse-power utils/safetyIdentifier.ts + chatPayload.ts
// applySafetyIdentifier. A per-end-user id attached to OpenAI-bound requests so
// one user's policy violation scopes to that user instead of blocking the whole
// platform account. HMAC-SHA256(credit_id) keyed with a secret that MUST match
// horse-power's SAFETY_IDENTIFIER_SECRET, so the identifier is identical across
// the enclave and cleartext paths (and reverse-lookupable during an incident).
// No-op when the secret is unset — no identifier beats a mismatched/weak one.

function isOpenAiFamilyModel(model) {
  return (
    typeof model === 'string' &&
    model.startsWith('openai/') &&
    !model.startsWith('openai/gpt-oss')
  );
}

function computeSafetyIdentifier(creditId, secret) {
  if (typeof creditId !== 'string' || creditId.length === 0) return null;
  if (!secret) return null;
  return createHmac('sha256', secret).update(creditId).digest('hex');
}

/**
 * Attach `payload.user = HMAC(credit_id)` for OpenAI-family models. The enclave
 * only serves /chat/completions, so we always use `user` (never the /responses
 * `safety_identifier` param). Ours overrides any caller-supplied `user` for
 * OpenAI models (must be authoritative); non-OpenAI models are left untouched.
 * Call AFTER transformPayload (model resolved) with the AUTHENTICATED credit_id
 * returned by horse-power authorize.
 */
export function applySafetyIdentifier(payload, creditId, secret) {
  if (!isOpenAiFamilyModel(payload?.model)) return;
  const identifier = computeSafetyIdentifier(creditId, secret);
  if (identifier === null) return;
  payload.user = identifier;
  delete payload.safety_identifier;
}

// ── Directive-applied payload strips (issue #6) ──────────────────────────────
// horse-power makes the DECISION at /authorize (it holds the live catalog + the
// static free list); the enclave applies the MECHANISM here on decrypted
// content. Both mirror the corresponding branch of chatPayload.ts transformPayload
// and MUST run AFTER transformPayload — a strip removes exactly what the web
// engine / provider routing already read, so the final payload is identical to
// hp's inline order (which strips before the web engine).
//
// DRIFT HAZARD: keep byte-identical to chatPayload.ts (guarded by the hp
// enclaveRoutingConformance test).

/**
 * PPQ-owned Auto Router config. Called with the `auto_router` directive from
 * hp's /authorize (issue horse-power#790, the allow-list half of #6).
 *
 * The allow-list is live Mongo config a pinned build cannot hold, so — like
 * strip_tools and is_free — hp decides it and the enclave applies it. Without
 * it, OpenRouter's router is unconstrained: measured against the live enclave
 * on 2026-08-24, the same prompt picked `anthropic/claude-sonnet-4.6` here
 * versus `deepseek/deepseek-v4-flash` on hp's path, ~28x the unit cost. The
 * list also carries a tool-capability invariant (every entry must support tool
 * calling) that an unconstrained pick can violate.
 *
 * The plugin body mirrors hp's exactly — `allowed_models` + `cost_tier` (hp
 * migrated off the older `cost_quality_tradeoff` number to the 'low'..'max'
 * band; legacy bodies pin to 'low'). Emitting the retired field here would be
 * silent drift, which is what the conformance test exists to prevent.
 *
 * The DIRECTIVE'S PRESENCE is the decision — this does not re-test the model,
 * exactly like applyFreeModelStrip/applyToolStrip. hp decides on the resolved
 * BASE slug (`is_auto_router`), because its normal path strips the literal
 * :exacto/:thinking/:extended suffix before the equivalent branch runs and so
 * DOES constrain suffixed Auto. `payload.model` here still carries that suffix,
 * so re-testing it would silently skip exactly those requests.
 *
 * A caller-supplied `auto-router` plugin wins, matching the per-request-beats-
 * defaults precedence OpenRouter itself applies — and matching hp exactly.
 *
 * Must run BEFORE applyFreeModelStrip: hp injects this inside transformPayload
 * (chatPayload.ts) well before its own free-model strip, and the strip deletes
 * `plugins` wholesale. Running it after would resurrect a plugin on a $0 model.
 *
 * DRIFT HAZARD: keep behaviourally identical to chatPayload.ts's
 * `openrouter/auto` branch (guarded by the hp enclaveRoutingConformance test).
 */
/** Cost bands hp emits; anything else is drift and must not reach OpenRouter. */
const COST_TIERS = new Set(['low', 'medium', 'high', 'xhigh', 'max']);
const MAX_ALLOWED_MODELS = 100;
export const MODEL_PATTERN = /^[a-zA-Z0-9*][a-zA-Z0-9_.:/*-]{0,127}$/;

/**
 * Validate hp's `auto_router` directive into the plugin's own shape, or null.
 *
 * Mirrors hp's producer-side rules (autoRouterConfig.service.ts) rather than
 * trusting the body: hp is trusted, but hp DRIFT is the realistic failure —
 * a renamed field or a retired cost format would otherwise become a plugin
 * OpenRouter 400s on, turning a config change into an outage. Rejecting
 * wholesale degrades to "no allow-list", which is the same as an older hp.
 */
export function parseAutoRouter(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const { allowed_models: models, cost_tier: tier } = raw;
  if (!Array.isArray(models) || models.length === 0) return null;
  if (models.length > MAX_ALLOWED_MODELS) return null;
  if (!models.every((m) => typeof m === 'string' && MODEL_PATTERN.test(m))) return null;
  if (typeof tier !== 'string' || !COST_TIERS.has(tier)) return null;
  return { allowed_models: [...models], cost_tier: tier };
}

export function applyAutoRouterConfig(payload, settings) {
  if (!settings) return;
  if (!Array.isArray(payload.plugins)) payload.plugins = [];
  if (payload.plugins.some((p) => p?.id === 'auto-router')) return;
  payload.plugins.push({
    id: 'auto-router',
    allowed_models: [...settings.allowed_models],
    cost_tier: settings.cost_tier,
  });
}

/** OpenRouter quantization labels (`fp8`, `bf16`, `mxfp4`, `unknown`, ...). */
const QUANTIZATION_PATTERN = /^[a-z0-9]{2,12}$/;
const MAX_FLOOR_QUANTIZATIONS = 16;

/**
 * Validate hp's `provider_floor` directive (hp services/orQualityFloor.ts,
 * #997), or null. Same posture as parseAutoRouter: a malformed floor degrades
 * to "no floor" — the pre-#997 body — never to a provider object OpenRouter
 * could 400 on.
 */
export function parseProviderFloor(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const q = raw.quantizations;
  if (!Array.isArray(q) || q.length === 0 || q.length > MAX_FLOOR_QUANTIZATIONS) return null;
  if (!q.every((v) => typeof v === 'string' && QUANTIZATION_PATTERN.test(v))) return null;
  return { quantizations: [...q] };
}

/**
 * Apply hp's chat-path `provider_directive` to the OpenRouter body. The
 * directive REPLACES the caller's provider object (hp never sees the body and
 * sends only `only` hard pins and derived-twin orders, so there is nothing of
 * the caller's to merge), with ONE exception: the caller's `zdr: true` is kept
 * on top, exactly as applyHardProviderPin does for the dialects. Before the
 * Oct 17-19 security reports (apienz, report 3/3) the replace dropped it, so a
 * ZDR request on a directive-pinned model (Gemini → Vertex) lost the flag;
 * Vertex happens to be ZDR, but the next pinned provider might not be, and
 * transformPayload's own re-apply reads the flag AFTER this runs. Call BEFORE
 * transformPayload. Returns whether a directive was applied.
 */
export function applyProviderDirective(payload, directive) {
  if (!directive || typeof directive !== 'object' || Array.isArray(directive)) return false;
  const callerZdr = payload.provider?.zdr === true;
  payload.provider = { ...directive, ...(callerZdr ? { zdr: true } : {}) };
  return true;
}

/**
 * Apply hp's provider_directive to a body the enclave relays VERBATIM (the
 * /v1/messages and /v1/responses dialects, #275/#280), but only when it is a
 * HARD pin (`only: [...]`, hp MODEL_OVERRIDES `onlyProviders`, #1060: every
 * google/gemini* model → `only: ['google-vertex']`, our BYOK key = GCP credits).
 * Without it these routes reached OpenRouter's default pool and landed on
 * Google AI Studio (OpenRouter cash).
 *
 * Soft directives (a derived twin's `order` preference) are left out on
 * purpose: these dialects never applied them, and widening that is its own
 * change. Unlike the chat path, the body is visible here, so the caller's
 * `zdr` is kept on top of the pin rather than dropped. Returns whether the pin
 * was applied. Verified live: OpenRouter's /api/v1/messages and
 * /api/v1/responses honor `provider.only`.
 */
export function applyHardProviderPin(body, directive) {
  if (!body || typeof body !== 'object') return false;
  if (!directive || typeof directive !== 'object' || Array.isArray(directive)) return false;
  if (!Array.isArray(directive.only) || directive.only.length === 0) return false;
  const callerZdr = body.provider?.zdr === true;
  body.provider = {
    ...directive,
    only: [...directive.only],
    ...(Array.isArray(directive.ignore) ? { ignore: [...directive.ignore] } : {}),
    ...(callerZdr ? { zdr: true } : {}),
  };
  return true;
}

/**
 * Merge the quality floor into the OpenRouter body's provider object. An
 * explicit caller choice or hard pin wins (`quantizations`, `only`, `zdr`, or
 * an `order` without fallbacks), and a non-object `provider` is never touched. Byte-parity port of hp
 * chatPayload.ts applyProviderFloor. Call AFTER transformPayload.
 */
export function applyProviderFloor(payload, floor) {
  const quantizations = floor?.quantizations;
  if (!Array.isArray(quantizations) || quantizations.length === 0) return;
  const p = payload.provider;
  if (p != null && (typeof p !== 'object' || Array.isArray(p))) return;
  if (p?.quantizations !== undefined || p?.only !== undefined) return;
  // Already a hard pin: a ZDR set or a no-fallback order is a curated host list
  // the floor could only empty, never improve.
  if (p?.zdr === true || (Array.isArray(p?.order) && p?.allow_fallbacks === false)) return;
  payload.provider = { ...(p ?? {}), quantizations: [...quantizations] };
}

/**
 * Spend cap (billing hardening, 2026-09-10; `n` added Oct 2026). hp's
 * `max_tokens_cap` is the most output the balance pays for on THIS request.
 * Two knobs decide how much output a chat body can ask for: the per-choice
 * length (`max_tokens`, or `max_completion_tokens` under its newer name) and
 * the number of choices (`n`). The cap used to clamp only the first, so
 * `{max_tokens: 4000, n: 8}` against a cap of 100 went upstream as
 * `{max_tokens: 100, n: 8}`: 800 tokens of output against a hold sized for
 * 100, exactly the failure the cap exists to prevent (the debit floor rejects
 * the settle after the answer has gone out). OpenRouter ignores `n`, but the
 * direct providers that honour it (Fireworks) are reached through the same
 * body. Reported in the Oct 17-19 security reports (Malik Werkudhara; Risky
 * Dwi Saputra noted the same arithmetic).
 *
 * Mutates `payload` in place. Returns `{ n }`: the bounded choice count when
 * `n` had to be reduced, else `undefined` -- the trace records it so hp can
 * see when a request asked for more than its balance.
 *
 * `n` is bounded AFTER the length is capped, by floor(cap / per-choice length),
 * never below 1: a request already at the full cap gets one completion, and
 * `n > 1` survives only when there is headroom. Anything that is not a
 * positive integer is dropped (equivalent to the API default of 1) rather
 * than forwarded for the provider to coerce.
 */
export function applySpendCap(payload, cap) {
  const requested = payload.max_tokens ?? payload.max_completion_tokens;
  const capped = Number.isFinite(requested) && requested > 0 ? Math.min(requested, cap) : cap;
  if (payload.max_completion_tokens != null && payload.max_tokens == null) {
    payload.max_completion_tokens = capped;
  } else {
    payload.max_tokens = capped;
    if (payload.max_completion_tokens != null) payload.max_completion_tokens = capped;
  }
  if (payload.n === undefined) return { n: undefined };
  if (!Number.isInteger(payload.n) || payload.n < 1) {
    delete payload.n;
    return { n: undefined };
  }
  if (payload.n === 1) return { n: undefined };
  const perChoice = Math.max(1, capped);
  const bounded = Math.max(1, Math.floor(cap / perChoice));
  if (bounded >= payload.n) return { n: undefined };
  payload.n = bounded;
  return { n: bounded };
}

/**
 * A tool entry that runs a paid web search: OpenRouter's server tool, or
 * Anthropic's dated `web_search_YYYYMMDD` tool (and OpenAI's
 * `web_search_preview`), which OpenRouter forwards and bills the same way.
 * The dated form was missed until the Oct 17-19 security reports: hp's
 * `:online` directive on the Messages dialect injects exactly that tool, and a
 * caller can send it on the chat path too.
 */
export function isPaidWebSearchTool(t) {
  const type = t?.type;
  return typeof type === 'string' && (type === 'openrouter:web_search' || type.startsWith('web_search'));
}

/**
 * Free-model strip. Called when hp's /authorize returns is_free=true: drop paid
 * plugins + every web_search tool (and a tool_choice targeting one) so PPQ
 * never pays for a plugin on a $0-billed request.
 */
export function applyFreeModelStrip(payload) {
  if (payload.plugins) delete payload.plugins;
  if (Array.isArray(payload.tools)) {
    const hadWebSearch = payload.tools.some(isPaidWebSearchTool);
    payload.tools = payload.tools.filter((t) => !isPaidWebSearchTool(t));
    if (payload.tools.length === 0) delete payload.tools;
    // Drop a tool_choice left pointing at the tool we just removed. Without
    // this the upstream rejects the whole request, which is worse than losing
    // web search: hp's normal path deletes it here for exactly that reason
    // (chatPayload.ts, "degrade cleanly instead"). The earlier version only
    // cleared tool_choice when the tools array emptied, so a request that named
    // web_search alongside other tools kept an unsatisfiable choice and 400'd.
    if (hadWebSearch && (!payload.tools || toolChoiceTargetsWebSearch(payload.tool_choice))) {
      delete payload.tool_choice;
    }
  }
}

/**
 * hp chatPayload.ts toolChoiceTargetsWebSearch, widened to the dated tool the
 * strip above now removes (a choice naming a tool that is gone is a 400).
 */
function toolChoiceTargetsWebSearch(choice) {
  return (
    isPaidWebSearchTool(choice) ||
    choice?.function?.name === 'openrouter:web_search' ||
    (choice?.type === 'tool' && choice?.name === 'web_search')
  );
}

/**
 * Tool-support strip. Called when hp's /authorize returns strip_tools=true (the
 * model's catalog entry has no `tools` support): remove tools/tool_choice so
 * OpenRouter doesn't 400 on an unsupported param. Only strips a non-empty tools
 * array, matching hp's guard exactly.
 */
/**
 * The `:online` suffix as hp's directive (horse-power #1055): add the `web`
 * plugin, exactly what hp's transformPayload injects for the suffix on its own
 * path. hp peels the suffix off `resolved_model` with every other routing
 * suffix, so this directive is the only trace of it the enclave receives.
 *
 * Applied to the neutral payload BEFORE the snapshot and transformPayload, as
 * hp injects it before its own web-search rules: direct-provider eligibility
 * then sees the plugin (web_search_requires_openrouter), and the #676 / #2550
 * swaps and the Exa defaults treat it like a plugin the caller sent. A caller
 * that already sent the plugin keeps theirs, options and all.
 */
export function applyWebPluginDirective(payload) {
  if (!Array.isArray(payload.plugins)) payload.plugins = [];
  if (!payload.plugins.some(isActiveWebPlugin)) {
    // `:online` is the explicit ask; a disabled `web` entry sent beside it
    // would otherwise be left to contradict the one injected here (mirrors
    // hp's transformPayload injection, horse-power #1094).
    payload.plugins = payload.plugins.filter((p) => p?.id !== 'web');
    payload.plugins.push({ id: 'web' });
  }
}

export function applyToolStrip(payload) {
  if (Array.isArray(payload.tools) && payload.tools.length > 0) {
    delete payload.tools;
    delete payload.tool_choice;
  }
}
