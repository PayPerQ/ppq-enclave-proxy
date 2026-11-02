// The reasoning effort a request names, for the authorize body (hp #1198).
//
// horse-power sizes the output floor it refuses always-on thinking models
// below (outputTokenCap.ts) from the prompt AND from how hard the model was
// asked to think: a 57k-token prompt at effort `high` needs room for more
// reasoning than the same prompt at `low` before any visible text appears.
// Authorize never saw the effort before this module, so the floor could not
// depend on it (Chatwoot 2152: two Fable turns, caps of 46k and 36k tokens,
// every one spent reasoning, both billed in full with nothing visible).
//
// This is an ENUM, never content: one of six words or nothing. hp treats an
// absent or unknown value as the web app's default (`medium`), so an older hp
// ignores the field and an older enclave keeps authorizing exactly as before.
import { canonicalizeReasoningObject } from './eligibility.mjs';
import { effortForBudget } from './anthropic.mjs';

/** The vocabulary hp accepts (outputTokenCap.ts REASONING_EFFORTS). */
export const REASONING_EFFORTS = Object.freeze(['minimal', 'low', 'medium', 'high', 'xhigh', 'max']);

/**
 * Allow-listed, EXACTLY as written: the body is forwarded unchanged, so hp
 * must be told the effort the upstream will see, not a cleaned-up reading of
 * it. `"HIGH"` or `" high "` is whatever the provider makes of it (OpenAI
 * 400s on it); here it names nothing, and hp sizes the floor at its default.
 */
export function normalizeReasoningEffort(raw) {
  return typeof raw === 'string' && REASONING_EFFORTS.includes(raw) ? raw : undefined;
}

/**
 * The effort a chat-completions body names. OpenRouter's `reasoning` object
 * wins over a legacy top-level `reasoning_effort`, exactly as
 * projectAllowedFields resolves the two for the upstream body (a budget
 * maps through the same tiers; `enabled: true` alone reads as medium).
 */
export function chatReasoningEffort(payload) {
  if (!payload || typeof payload !== 'object') return undefined;
  if (payload.reasoning !== undefined) {
    const canon = canonicalizeReasoningObject(payload.reasoning);
    if (canon.effort !== undefined) return normalizeReasoningEffort(canon.effort);
    if (canon.bailMember !== undefined) return undefined;
  }
  return normalizeReasoningEffort(payload.reasoning_effort);
}

/**
 * The effort a `/v1/responses` body names: `reasoning.effort` (OpenAI's own
 * vocabulary — minimal | low | medium | high | xhigh), nothing else.
 */
export function responsesReasoningEffort(body) {
  return normalizeReasoningEffort(body?.reasoning?.effort);
}

/**
 * The effort a `/v1/messages` body names: `output_config.effort` (the dial
 * that replaced budgets on adaptive-thinking models), else an enabled
 * `thinking.budget_tokens` mapped through the Anthropic translator's tiers.
 * `thinking: { type: 'disabled' }` or no thinking at all names nothing.
 *
 * An explicit `output_config.effort` that is not in the vocabulary names
 * nothing and does NOT fall through to the budget: the translators treat it
 * as unmappable (responsesMessages.mjs reasoningEffortFor bails on it), so
 * reading a budget in its place would tell hp an effort no upstream sees.
 *
 * Budget tiers: anthropic.mjs says `xhigh` above 32k where the OpenAI
 * Messages translator says `high`; hp's floor gives both the same
 * multiplier (outputTokenCap.ts THINKING_FLOOR_INPUT_MULTIPLIER), so the
 * floor is the same whichever upstream the request lands on.
 */
export function messagesReasoningEffort(body) {
  const oc = body?.output_config;
  if (oc && typeof oc === 'object' && oc.effort !== undefined) {
    return normalizeReasoningEffort(oc.effort);
  }
  const thinking = body?.thinking;
  if (!thinking || typeof thinking !== 'object' || thinking.type !== 'enabled') return undefined;
  const budget = thinking.budget_tokens;
  if (!Number.isInteger(budget) || budget <= 0) return undefined;
  return normalizeReasoningEffort(effortForBudget(budget));
}

/** Dispatch by dialect name (`MESSAGES_DIALECT.name` / `RESPONSES_DIALECT.name`). */
export function dialectReasoningEffort(dialectName, body) {
  if (dialectName === 'messages') return messagesReasoningEffort(body);
  if (dialectName === 'responses') return responsesReasoningEffort(body);
  return undefined;
}
