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

/** Local free-model check (mirrors models.service.ts isFree: the `:free` suffix). */
function isFreeModel(model) {
  return typeof model === 'string' && model.endsWith(':free');
}

/**
 * DRIFT HAZARD: keep in sync with horse-power services/chatPayload.ts
 * transformPayload. Only model-string-based provider routing is ported (needs
 * no catalog). The catalog-dependent transforms — chatModelSupportsTools
 * stripping, applyWebSearchEngine, and short-slug alias resolution — are
 * intentionally NOT ported; requests relying on them should use the cleartext
 * path. Keep the ported branches identical to the source.
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

    const hasPlugins = payload.plugins?.length > 0;
    const webPlugin =
      Array.isArray(payload.plugins) && payload.plugins.some((p) => p?.id === 'web');
    const webSearchToolActive =
      Array.isArray(payload.tools) &&
      payload.tools.some((t) => t?.type === 'openrouter:web_search');
    // Opus 4.8 has no reachable Amazon Bedrock endpoint under our BYOK key.
    const bedrockUnavailable = payload.model === 'anthropic/claude-opus-4.8';
    const isFable = payload.model.includes('fable');

    if (isFable) {
      payload.provider = { order: ['anthropic'], allow_fallbacks: false };
    } else if (webPlugin && bedrockUnavailable) {
      payload.provider = { order: ['anthropic'], allow_fallbacks: false };
    } else if (hasPlugins || webSearchToolActive || bedrockUnavailable) {
      payload.provider = { ignore: ['amazon-bedrock'] };
    } else {
      payload.provider = { order: ['amazon-bedrock'], allow_fallbacks: false };
    }

    if (payload.model.startsWith('anthropic/claude-sonnet-4')) {
      payload.betas = ['context-1m-2025-08-07'];
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

  // Free models: strip paid plugins + the web_search tool (and a tool_choice
  // targeting it) so PPQ never pays for a plugin on a $0-billed request.
  if (isFreeModel(payload.model)) {
    if (payload.plugins) delete payload.plugins;
    if (Array.isArray(payload.tools)) {
      payload.tools = payload.tools.filter((t) => t?.type !== 'openrouter:web_search');
      if (payload.tools.length === 0) {
        delete payload.tools;
        delete payload.tool_choice;
      }
    }
  }

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
function addCachePromptMarks(messages) {
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
