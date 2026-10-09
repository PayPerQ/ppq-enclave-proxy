/**
 * Multi-upstream connector helpers (Phase 1b).
 *
 * hp's /enclave/authorize returns an ordered `upstreams` candidate list — a
 * direct provider (Fireworks) first, OpenRouter as the terminal fallback. These
 * helpers turn a DIRECT candidate + the neutral (pre-transformPayload) payload
 * into an outbound request, running the ported eligibility gate on the decrypted
 * body first. server.mjs drives the try-in-order loop + streaming.
 *
 * A direct attempt that is ineligible OR fails at any stage falls back to the
 * next candidate, so being conservative here only ever costs the direct
 * optimization — never a user-visible failure.
 */
import { createHash } from 'node:crypto';
import {
  FIREWORKS_HOSTED,
  evaluateDirectEligibility,
  isWebSearchServerTool,
  projectAllowedFields,
} from './eligibility.mjs';

/**
 * Provider credentials a candidate may ask the enclave to attach under a
 * header other than `authorization`, and the only host each may go to.
 *
 * Fireworks' FireRouter (horse-power #1034) forwards a Claude turn to
 * Anthropic with a credential the CALLER supplies per request
 * (`x-anthropic-api-key`; Provider Keys are not enabled on PPQ's Fireworks
 * account). hp's candidate names the header (`key_headers`); the value is
 * resolved HERE from the keys the enclave already holds, so key material
 * never rides the authorize answer, and a candidate cannot send the
 * Anthropic key anywhere but Fireworks. Measured code: a new entry is a
 * rotation, the same as a new tunnel.
 */
export const KEY_HEADERS = Object.freeze({
  'x-anthropic-api-key': Object.freeze({
    ref: 'anthropic',
    hosts: Object.freeze(['api.fireworks.ai']),
    // And only the route that justifies it: a plain Fireworks row has no
    // business carrying the Anthropic credential, whatever hp's candidate says.
    providers: Object.freeze(['firerouter']),
  }),
});

const EXTRA_HEADER_NAME_RE = /^[a-z0-9-]{1,64}$/;
const EXTRA_HEADER_VALUE_RE = /^[\x20-\x7E]{1,256}$/;
const EXTRA_HEADERS_MAX = 8;
/** Never settable by a candidate: the request's own framing and credential. */
const RESERVED_HEADERS = new Set(['authorization', 'host', 'content-type', 'content-length', 'transfer-encoding', 'connection']);

/**
 * The literal request headers a candidate asks for (`extra_headers`, e.g.
 * FireRouter's `x-routing-preference`), kept to a small, printable, lower-case
 * set that cannot touch the framing or credential headers. Anything outside
 * the shape is dropped rather than forwarded: hp is trusted for routing, but
 * a header is a wire fact this build should be able to account for.
 */
export function sanitizeExtraHeaders(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  let n = 0;
  for (const [name, value] of Object.entries(raw)) {
    if (n >= EXTRA_HEADERS_MAX) break;
    const key = String(name).toLowerCase();
    if (!EXTRA_HEADER_NAME_RE.test(key) || RESERVED_HEADERS.has(key) || KEY_HEADERS[key]) continue;
    if (typeof value !== 'string' || !EXTRA_HEADER_VALUE_RE.test(value)) continue;
    out[key] = value;
    n += 1;
  }
  return out;
}

/**
 * The served-id → public-slug map a router candidate carries
 * (`served_models`), shape-checked: slug-looking strings only, bounded.
 * Feeds the response rewriter (rebrand.mjs), never billing — the settle
 * reports the raw served id and hp prices it from its own table.
 */
const SERVED_ID_RE = /^[a-zA-Z0-9._:/@~-]{1,96}$/;
const SERVED_MODELS_MAX = 16;
export function sanitizeServedModels(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const out = {};
  let n = 0;
  for (const [served, slug] of Object.entries(raw)) {
    if (n >= SERVED_MODELS_MAX) break;
    if (!SERVED_ID_RE.test(served) || typeof slug !== 'string' || !SERVED_ID_RE.test(slug)) continue;
    out[served] = slug;
    n += 1;
  }
  return n > 0 ? out : undefined;
}

/**
 * Adapt an /authorize candidate (snake_case projection) to the `row` shape the
 * ported eligibility gate + projectAllowedFields expect (camelCase). hp only
 * offers enabled + circuit-healthy direct candidates, so enabled is always true.
 */
export function candidateToRow(candidate) {
  return {
    provider: candidate.provider,
    upstreamModelId: candidate.upstream_model,
    orSlug: candidate.or_slug,
    serviceTier: candidate.service_tier || '',
    supportsTools: candidate.supports_tools === true,
    supportsImageInput: candidate.supports_image_input === true,
    enabled: true,
    enabledOverride: null,
  };
}

/** True for the OpenRouter terminal fallback candidate. */
export function isOpenRouter(candidate) {
  return candidate?.provider === 'openrouter';
}

/**
 * hp's /authorize contract puts an OpenRouter candidate LAST in every list
 * (buildEnclaveUpstreams appends it unconditionally) — but the loop must not
 * 502 private-mode traffic over an hp bug or a future refactor that breaks
 * that contract. OpenRouter must be TERMINAL, not merely present: the loop
 * only pipes-regardless-of-status the LAST candidate, so a misplaced OR
 * entry would be drained on a 5xx like any direct candidate and the request
 * could still exhaust (CodeRabbit, this PR — presence alone was a
 * half-guard). Direct candidates keep their relative order; any OR entries
 * collapse into one terminal (reusing a misplaced one, synthesizing when
 * absent); an absent/empty list becomes the pure-OpenRouter singleton (the
 * pre-Phase-1b behavior). A list of only-skippable direct candidates (e.g.
 * vertex with no mintable token) then always has somewhere to fall.
 */
export function normalizeCandidates(upstreams) {
  const list = Array.isArray(upstreams) && upstreams.length > 0 ? upstreams : [];
  // No fast-path: an early return for already-terminal lists skipped the
  // dedupe, so [OR, OR] kept both entries — the invariant must hold by
  // construction on EVERY input (CodeRabbit, this PR, round three).
  const fallback = [...list].reverse().find(isOpenRouter) || { provider: 'openrouter' };
  return [...list.filter((candidate) => !isOpenRouter(candidate)), fallback];
}

/**
 * Build the outbound request for a DIRECT candidate, or a skip reason.
 *
 * @param basePayload the resolved-but-untransformed payload (what eligibility +
 *   projectAllowedFields operate on — NOT the OpenRouter-transformed one).
 * @param ports  host -> local vsock tunnel port (the enclave's registry;
 *   provider-name keys remain as a fallback for older hp candidate payloads)
 * @param keys   key_ref  -> provisioned upstream API key
 * @returns {opts, bodyStr, provider, orSlug, upstreamModel} on success,
 *          or {skip: <reason>, offendingField?} when this candidate can't be used.
 */
/**
 * Venice layers its OWN system prompt on top of the caller's unless told not
 * to: `venice_parameters.include_venice_system_prompt` is declared in Venice's
 * schema as a boolean defaulting to TRUE. These are exactly the uncensored
 * models this route exists to serve, so accepting that default would let an
 * upstream prompt we neither wrote nor version silently shape every answer,
 * and would make the same weights behave differently here than on
 * horse-power's direct path, which has always sent the flag
 * (services/directProviders/veniceAdapter.ts).
 *
 * It is also a BILLING defect, which is how this was found. Measured in
 * production on 2026-09-23, minutes after Venice was first keyed on the
 * enclave: "Say hello in five words." to `venice/gemma-4-uncensored` billed
 * 19 input tokens through horse-power and 1578 through here — Venice's own
 * prompt, ~1560 tokens, charged to the caller on every request, about 38x the
 * price for the identical answer.
 *
 * A caller cannot re-enable it: `venice_parameters` is not an allowed field,
 * so projectAllowedFields has already dropped any copy of it before this runs,
 * and this assignment is the only writer. Web search joins THIS object rather
 * than a second assignment, because `venice_parameters` is one JSON member and
 * a later whole-object assignment would silently drop the flag.
 */

/**
 * The one field in the shared allowlist that Venice's schema does not declare
 * (`additionalProperties: false` at its root), so forwarding it is a certain
 * 400. Skipped with the field named rather than stripped: dropping a caller's
 * `logit_bias` would change what the model sees while reporting success.
 * Mirror of hp veniceAdapter.ts VENICE_UNSUPPORTED_FIELDS.
 */
export const VENICE_UNSUPPORTED_FIELDS = new Set(['logit_bias']);

/**
 * Image media types Venice accepts. Narrower than the shared gate, which also
 * admits heic/heif for the providers that take them: Venice answers those
 * with a 400. Mirror of hp veniceAdapter.ts.
 */
const VENICE_IMAGE_DATA_URI_RE = /^data:image\/(png|jpeg|webp);base64,/;

/**
 * Images per message when hp's candidate does not say. One is what every
 * Venice vision row accepts, so an older hp (no `max_images_per_message`)
 * can only under-admit here, never forward a request Venice will refuse.
 */
export const VENICE_DEFAULT_MAX_IMAGES_PER_MESSAGE = 1;

function isVeniceCandidate(candidate) {
  return candidate?.provider === 'venice' || candidate?.host === 'api.venice.ai';
}

/**
 * The Venice wire value for a caller's web-search intent, or undefined when
 * they asked for none. Mirror of hp veniceAdapter.ts `veniceWebSearchMode`.
 *
 *   ON   -> `plugins: [{ id: 'web' }]`     always search
 *   AUTO -> `tools: [{ type: 'web_search' }]`
 *
 * Both map to `'on'`, never `'auto'`: hp measured Venice's `auto` firing on
 * the most trivial prompt, and every turn it fires on carries the per-search
 * surcharge — a mode whose price is a coin flip is not one a caller can
 * reason about. The web app does not offer Auto on these rows; the tool form
 * is reachable only by an API caller who put it in their own `tools`.
 */
export function veniceWebSearchMode(payload) {
  const plugins = payload?.plugins;
  if (Array.isArray(plugins) && plugins.some((p) => p?.id === 'web')) return 'on';
  const tools = payload?.tools;
  if (Array.isArray(tools) && tools.some(isWebSearchServerTool)) return 'on';
  return undefined;
}

/**
 * Why this request's images cannot ride the Venice wire, as a skip, or
 * undefined when they can. The shared gate already decided WHETHER the row
 * takes images; these are Venice's limits on top — forwarded, each is a
 * certain upstream 400. The count is per MESSAGE, as hp probed it. Mirror of
 * hp veniceAdapter.ts `veniceImageBail`.
 */
export function veniceImageSkip(messages, maxImagesPerMessage) {
  if (!Array.isArray(messages)) return undefined;
  for (const message of messages) {
    const content = message?.content;
    if (!Array.isArray(content)) continue;
    let images = 0;
    for (const part of content) {
      if (part?.type !== 'image_url') continue;
      const url = typeof part.image_url === 'string' ? part.image_url : part.image_url?.url;
      if (typeof url !== 'string' || !VENICE_IMAGE_DATA_URI_RE.test(url)) {
        return { skip: 'non_text_content', offendingField: 'image_media_type' };
      }
      images += 1;
    }
    if (images > maxImagesPerMessage) {
      return { skip: 'too_many_images', offendingField: String(maxImagesPerMessage) };
    }
  }
  return undefined;
}

/**
 * Venice's request shape, applied to the projected body in place. Returns a
 * skip when the request cannot ride this wire, undefined otherwise. A skip is
 * a failed request for a `venice/*` model — there is no OpenRouter twin — which
 * is the honest outcome for a request this route cannot honour.
 */
function applyVeniceParameters(body, candidate, basePayload) {
  if (!isVeniceCandidate(candidate)) return undefined;

  // The web-search SERVER TOOL is not a function tool and must never reach
  // Venice: its `tools` schema describes functions. Its meaning is not lost,
  // it moves into `enable_web_search` below. An emptied array is deleted.
  const webSearch = veniceWebSearchMode(basePayload);
  if (Array.isArray(body.tools)) {
    body.tools = body.tools.filter((t) => !isWebSearchServerTool(t));
    if (body.tools.length === 0) delete body.tools;
  }

  for (const key of Object.keys(body)) {
    if (VENICE_UNSUPPORTED_FIELDS.has(key)) return { skip: 'unmappable_field', offendingField: key };
  }

  const maxImages =
    Number.isInteger(candidate.max_images_per_message) && candidate.max_images_per_message >= 0
      ? candidate.max_images_per_message
      : VENICE_DEFAULT_MAX_IMAGES_PER_MESSAGE;
  const imageSkip = veniceImageSkip(body.messages, maxImages);
  if (imageSkip) return imageSkip;

  // `include_search_results_in_stream` is what makes the citations reachable:
  // without it the search still runs and still bills, but the citation frame
  // never arrives, so the user sees sourceless claims and the settle has no
  // evidence a search ran (veniceCitations.mjs counts from that frame).
  // `enable_web_citations` stays at its default: it interleaves `^1,4^`
  // superscripts the web app does not parse.
  body.venice_parameters = {
    include_venice_system_prompt: false,
    ...(webSearch
      ? { enable_web_search: webSearch, include_search_results_in_stream: true }
      : {}),
  };
  return undefined;
}

/**
 * Opaque, stable per-conversation key for Fireworks' `x-session-affinity`
 * header (#286). Fireworks' prompt cache lives inside ONE replica; without a
 * hint the serverless balancer can land successive turns of a conversation on
 * different replicas and every such turn is a full cache miss (measured: ~3-4%
 * of follow-up turns in production, 1-4% in A/B depending on load).
 *
 * The key is sha256(credit_id + the first two messages' role and text, each
 * truncated to 8 KiB), so it is the same for every turn of a conversation (a
 * conversation only ever APPENDS messages) and different for different users
 * of the same prompt. What Fireworks learns from it is a pseudonymous
 * per-credit, per-prefix routing token: it cannot recover the credit id or
 * the text, but it can tell that two requests belong to the same conversation
 * (which the identical prefix in the plaintext body already shows it). It is
 * never logged, settled or traced.
 *
 * Deliberate limits: only text parts of array content are hashed (an
 * image-only first message keys on role alone, which only costs cache
 * stickiness, never correctness), and two same-credit conversations that
 * share the first 8 KiB of their opening messages share a key, which merely
 * routes them to the same replica. Returns undefined when there is nothing
 * to key on.
 */
export function computeSessionAffinity(creditId, messages) {
  if (!Array.isArray(messages) || messages.length === 0) return undefined;
  const h = createHash('sha256');
  h.update(String(creditId || ''));
  for (const m of messages.slice(0, 2)) {
    const c = m?.content;
    const text =
      typeof c === 'string'
        ? c
        : Array.isArray(c)
          ? c.map((part) => (typeof part?.text === 'string' ? part.text : '')).join('\n')
          : '';
    // Length-prefixed so a text containing NUL cannot impersonate a role or a
    // second message (CodeRabbit on #287); the effect of such a collision is
    // only shared replica routing, but the encoding should still be unambiguous.
    const t = text.slice(0, 8192);
    h.update('\0' + String(m?.role || '') + '\0' + t.length + '\0' + t);
  }
  return h.digest('hex').slice(0, 32);
}

/**
 * Shape one direct-provider request from the caller's OpenAI-style payload:
 * eligibility check, allowed-field projection, provider-specific parameter
 * fixes, and the TLS-tunnel connection options. `affinity` (optional) is the
 * per-conversation key from computeSessionAffinity; it is sent only to
 * Fireworks as `x-session-affinity`. Returns `{ skip, offendingField }` when
 * the request cannot ride this candidate, else the built request spec.
 */
export function buildDirectRequest({ candidate, basePayload, ports, keys, affinity }) {
  const port = ports?.[candidate.host] ?? ports?.[candidate.provider];
  const key = keys?.[candidate.key_ref];
  // No tunnel or key provisioned for this provider (e.g. before the host is
  // configured) → skip cleanly so the request falls back to OpenRouter.
  if (!port || !key) return { skip: 'no_tunnel_or_key' };

  const row = candidateToRow(candidate);
  const elig = evaluateDirectEligibility({
    payload: basePayload,
    path: '/chat/completions',
    modelSuffixes: [],
    row,
  });
  if (!elig.eligible) {
    return { skip: elig.reason || 'ineligible', offendingField: elig.offendingField };
  }

  const body = projectAllowedFields(basePayload, row);
  const veniceSkip = applyVeniceParameters(body, candidate, basePayload);
  if (veniceSkip) return veniceSkip;

  // Headers the candidate asks for beyond the bearer key: literal values
  // (sanitized) and named provider credentials (resolved here, host-bound).
  // A credential this build cannot attach is a skip, not a request sent
  // without it: FireRouter would answer a Claude turn with 400
  // `no usable anthropic credential`, and the direct-only refusal says
  // "unavailable" more truthfully than relaying that.
  const extraHeaders = sanitizeExtraHeaders(candidate.extra_headers);
  if (Array.isArray(candidate.key_headers)) {
    for (const name of candidate.key_headers) {
      const rule = typeof name === 'string' ? KEY_HEADERS[name.toLowerCase()] : undefined;
      if (
        !rule ||
        !rule.hosts.includes(candidate.host) ||
        !rule.providers.includes(candidate.provider) ||
        !keys?.[rule.ref]
      ) {
        return { skip: 'no_tunnel_or_key' };
      }
      extraHeaders[name.toLowerCase()] = keys[rule.ref];
    }
  }

  const bodyStr = JSON.stringify(body);
  return {
    provider: candidate.provider,
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
    servedModels: sanitizeServedModels(candidate.served_models),
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
        'content-length': Buffer.byteLength(bodyStr),
        authorization: `Bearer ${key}`,
        ...extraHeaders,
        // Fireworks only: keep every turn of a conversation on the replica
        // that holds its prompt cache (#286). Other direct hosts ignore or
        // reject unknown headers, so the hint is scoped to the one that
        // documents it.
        ...(FIREWORKS_HOSTED.has(candidate.provider) && affinity
          ? { 'x-session-affinity': affinity }
          : {}),
      },
    },
  };
}
