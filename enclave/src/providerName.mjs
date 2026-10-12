/**
 * The provider name OpenRouter reports it routed to ("OpenAI", "Google AI
 * Studio", "Amazon Bedrock", ...). A display name, not an identifier, so the
 * shape is a short run of word characters, spaces and . ( ) / - — anything
 * else (or longer) is not a provider name and is dropped.
 *
 * Shared by every dialect that reports it (chat via cost.mjs, Messages via
 * messages.mjs) so the gate on what reaches the settle cannot drift.
 */
const PROVIDER_NAME_RE = /^[\w .()/-]{1,64}$/;

export function providerName(value) {
  return typeof value === 'string' && PROVIDER_NAME_RE.test(value) ? value : undefined;
}
