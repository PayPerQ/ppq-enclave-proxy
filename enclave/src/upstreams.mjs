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
import { evaluateDirectEligibility, projectAllowedFields } from './eligibility.mjs';

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
 * that contract. A list without the terminal gains one; an absent/empty list
 * becomes the pure-OpenRouter singleton (the pre-Phase-1b behavior). A list
 * of only-skippable direct candidates (e.g. vertex with no mintable token)
 * then always has somewhere to fall.
 */
export function normalizeCandidates(upstreams) {
  const list = Array.isArray(upstreams) && upstreams.length > 0 ? upstreams : [];
  return list.some(isOpenRouter) ? list : [...list, { provider: 'openrouter' }];
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
export function buildDirectRequest({ candidate, basePayload, ports, keys }) {
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
  const bodyStr = JSON.stringify(body);
  return {
    provider: candidate.provider,
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
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
      },
    },
  };
}
