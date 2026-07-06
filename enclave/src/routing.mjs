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

export function transformPayload(payload) {
  if (typeof payload.model !== 'string') {
    throw new Error('Invalid payload: model must be a string');
  }

  if (payload.model.includes('anthropic')) {
    if (Array.isArray(payload.messages)) {
      addCachePromptMarks(payload.messages);
    }
    const hasPlugins = payload.plugins?.length > 0;
    const bedrockUnavailable = payload.model === 'anthropic/claude-opus-4.7';
    if (hasPlugins || bedrockUnavailable) {
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

  // Always ask OpenRouter to include usage so we can bill from the stream.
  payload.usage = { ...(payload.usage || {}), include: true };
}

/**
 * Inject Anthropic ephemeral cache_control marks on the first message and the
 * last two user messages (mirrors addCachePromptMarks in models.service.ts),
 * respecting any cache blocks the caller already set.
 */
function addCachePromptMarks(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return;

  const markContent = (msg) => {
    if (!msg) return;
    if (typeof msg.content === 'string') {
      msg.content = [
        {
          type: 'text',
          text: msg.content,
          cache_control: { type: 'ephemeral' },
        },
      ];
      return;
    }
    if (Array.isArray(msg.content)) {
      const alreadyMarked = msg.content.some((b) => b && b.cache_control);
      if (alreadyMarked) return;
      const lastText = [...msg.content]
        .reverse()
        .find((b) => b && b.type === 'text');
      if (lastText) lastText.cache_control = { type: 'ephemeral' };
    }
  };

  markContent(messages[0]);
  const userIdx = messages
    .map((m, i) => (m.role === 'user' ? i : -1))
    .filter((i) => i >= 0);
  for (const i of userIdx.slice(-2)) markContent(messages[i]);
}
