/**
 * Model resolution + payload transforms.
 *
 * A trimmed, dependency-free port of horse-power's services/chatPayload.ts.
 * These operate on decrypted content, so they MUST run inside the enclave.
 *
 * PoC scope: provider-routing transforms + usage.include. AutoClaw/AutoRouter
 * smart routing (which pulls in @blockrun/clawrouter) is intentionally excluded
 * from v1 to keep the trusted codebase small and auditable; those models are
 * rejected here and continue to use the cleartext path until ported.
 */

import { createHmac } from 'node:crypto';
import {
  applyWebSearchEngine,
  swapWebPluginForServerTool,
  swapWebSearchToolForPlugin,
  webPluginBreaksModel,
} from './webSearchTransforms.mjs';

export function resolveModel(payload) {
  if (payload.model && typeof payload.model === 'object' && payload.model.id) {
    payload.model = payload.model.id;
  }
  if (typeof payload.model !== 'string') {
    throw new Error('Invalid payload: model must be a string');
  }
  if (
    payload.model.startsWith('autoclaw/') ||
    payload.model.startsWith('autorouter/')
  ) {
    throw new Error(
      'Smart-routing models are not yet supported by the enclave proxy',
    );
  }
  if (payload.model.startsWith('private/')) {
    throw new Error('private/* models use the Tinfoil path, not this proxy');
  }
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

    const hasPlugins = payload.plugins?.length > 0;
    const webPlugin =
      Array.isArray(payload.plugins) && payload.plugins.some((p) => p?.id === 'web');
    const webSearchToolActive =
      Array.isArray(payload.tools) &&
      payload.tools.some((t) => t?.type === 'openrouter:web_search');
    // Opus 5's usable Bedrock capacity is the `amazon-bedrock/claude-on-aws`
    // endpoint, which our AWS BYOK key does NOT cover — the pin below would
    // land there and burn OpenRouter credits (the #566 failure mode; the old
    // "flaky 502s" label was this same coverage gap). Opus 4.8 was removed
    // 2026-08-17 (stale premise; live-verified healthy on Bedrock). Keep in
    // sync with horse-power chatPayload.ts.
    const bedrockUnavailable = payload.model === 'anthropic/claude-opus-5';
    const isFable = payload.model.includes('fable');

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

  if (payload.model.includes('gemini-2.5-flash')) {
    payload.provider = { ignore: ['google-vertex', 'venice'] };
  } else if (
    !payload.provider &&
    !payload.model.startsWith(
      'cognitivecomputations/dolphin-mistral-24b-venice-edition',
    )
  ) {
    payload.provider = { ignore: ['venice'] };
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

/**
 * Inject Anthropic ephemeral cache_control marks on the first message and the
 * last two user messages. Mirrors addCachePromptMarks in horse-power's
 * services/models.service.ts, INCLUDING the issue #674 fix: never mark an empty
 * or whitespace-only text block. Anthropic rejects the entire request with a
 * 400 ("cache_control cannot be set for empty text blocks", surfaced as
 * "Provider returned error"), so a skipped breakpoint (some lost cache reuse) is
 * always preferable to synthesising or marking an empty block.
 *
 * DRIFT HAZARD: keep in sync with models.service.ts addCachePromptMarks.
 */
export function addCachePromptMarks(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return;

  // GLOBAL check: if the caller already sent cache_control anywhere, respect it
  // and add none. Clients like Claude Code manage their own breakpoints, and
  // extra marks would exceed the provider's 4-block cache_control limit.
  const hasExistingCacheControl = messages.some(
    (msg) =>
      msg.cache_control ||
      (Array.isArray(msg.content) &&
        msg.content.some((block) => block && block.cache_control)),
  );
  if (hasExistingCacheControl) return;

  // Mark the last NON-EMPTY text part only. Empty/whitespace text is skipped
  // entirely (never converted into a marked block) — that empty marked block is
  // the #674 hard 400.
  const markLastNonEmptyTextPart = (msg) => {
    if (!msg) return;
    if (typeof msg.content === 'string') {
      if (!msg.content.trim()) return;
      msg.content = [{ type: 'text', text: msg.content }];
    }
    if (Array.isArray(msg.content)) {
      const lastTextPart = msg.content
        .filter(
          (part) =>
            part &&
            part.type === 'text' &&
            typeof part.text === 'string' &&
            part.text.trim(),
        )
        .pop();
      if (lastTextPart) lastTextPart.cache_control = { type: 'ephemeral' };
    }
  };

  markLastNonEmptyTextPart(messages[0]);
  for (const msg of messages.filter(({ role }) => role === 'user').slice(-2)) {
    markLastNonEmptyTextPart(msg);
  }
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
const MODEL_PATTERN = /^[a-zA-Z0-9*][a-zA-Z0-9_.:/*-]{0,127}$/;

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

/**
 * Free-model strip. Called when hp's /authorize returns is_free=true: drop paid
 * plugins + the web_search tool (and a tool_choice targeting it) so PPQ never
 * pays for a plugin on a $0-billed request.
 */
export function applyFreeModelStrip(payload) {
  if (payload.plugins) delete payload.plugins;
  if (Array.isArray(payload.tools)) {
    const hadWebSearch = payload.tools.some((t) => t?.type === 'openrouter:web_search');
    payload.tools = payload.tools.filter((t) => t?.type !== 'openrouter:web_search');
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

/** hp chatPayload.ts toolChoiceTargetsWebSearch — kept identical on purpose. */
function toolChoiceTargetsWebSearch(choice) {
  return (
    choice?.type === 'openrouter:web_search' ||
    choice?.function?.name === 'openrouter:web_search'
  );
}

/**
 * Tool-support strip. Called when hp's /authorize returns strip_tools=true (the
 * model's catalog entry has no `tools` support): remove tools/tool_choice so
 * OpenRouter doesn't 400 on an unsupported param. Only strips a non-empty tools
 * array, matching hp's guard exactly.
 */
export function applyToolStrip(payload) {
  if (Array.isArray(payload.tools) && payload.tools.length > 0) {
    delete payload.tools;
    delete payload.tool_choice;
  }
}
