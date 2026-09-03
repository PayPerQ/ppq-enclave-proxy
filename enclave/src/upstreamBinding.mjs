// Family-level upstream binding — the part of #58 that PREVENTS substitution
// rather than merely recording it.
//
// WHAT WAS AND WAS NOT ALREADY PREVENTED
// --------------------------------------
// `UPSTREAM_PORTS` in server.mjs is already a de-facto host allowlist: a
// candidate naming a host absent from it gets no tunnel and is skipped, and the
// parent's vsock-proxy allowlist independently constrains the same set. So
// horse-power CANNOT direct a request to an arbitrary endpoint.
//
// What it can do is PAIR any model family with any of those hosts. Nothing
// stopped an `anthropic/*` request being sent to `api.fireworks.ai`. That is
// the realistic fraud — an expensive model served by a cheap provider — and it
// is what this file refuses.
//
// WHY THE MAP IS DELIBERATELY MINIMAL
// -----------------------------------
// Issue #7 is explicit that catalog-dependent logic must stay in horse-power:
// the enclave has three dependencies and a reproducible build, hp holds the
// live catalog, and duplicating the catalog here is how the two drift. This map
// is therefore NOT a catalog. It keys on the VENDOR NAMESPACE of a model id
// (`anthropic/`, `openai/`, `google/`), which is a stable naming convention
// rather than a catalog fact, and it covers only namespaces whose canonical
// direct provider is unambiguous.
//
// Everything else is unconstrained among the hosts the enclave can reach at
// all. That is the conservative direction: an absent rule permits what already
// worked, while a wrong rule costs the OpenRouter margin on some traffic and
// never an outage.
//
// FAIL-SAFE, NOT FAIL-STOP
// ------------------------
// A violating candidate is SKIPPED, not fatal. OpenRouter is permitted for
// every family and is the terminal candidate in every list, so the request
// still gets served — it just cannot be served by the substituted provider.
// Denying the substitution must not become a way to deny the user their answer.
//
// The denial is recorded in the routing receipt and reported to hp through the
// content-free error channel, because a silent refusal would be indistinguishable
// from a provider being down.

/** Always permitted: the terminal fallback for every model. */
const UNIVERSAL = 'openrouter.ai';

/**
 * Vendor namespace -> the direct hosts it may reach, besides OpenRouter.
 *
 * Keys are matched as a prefix of the requested model id. Add a namespace only
 * when its canonical direct provider is not in doubt.
 */
export const FAMILY_BINDINGS = Object.freeze({
  // Anthropic models go direct to Anthropic's Messages API, or via OpenRouter.
  'anthropic/': ['api.anthropic.com'],
  // OpenAI frontier models are served from Bedrock's OpenAI-Responses surface
  // (bedrock-mantle), the only endpoint that carries them. Two regions are
  // provisioned, so both are legitimate.
  'openai/': ['bedrock-mantle.us-east-1.api.aws', 'bedrock-mantle.us-east-2.api.aws'],
  // Google models go direct to Vertex.
  'google/': ['aiplatform.googleapis.com'],
});

/**
 * Is this pairing of requested model and upstream host permitted?
 *
 * @param {string} requestedModel the id the CLIENT asked for, not the wire id
 * @param {string} host           the hostname the enclave would validate TLS against
 * @returns {{allowed: boolean, family?: string, permitted?: string[]}}
 */
export function checkBinding(requestedModel, host) {
  if (typeof host !== 'string' || host.length === 0) {
    // No host to judge. The builder will skip this candidate for want of a
    // tunnel anyway; refusing here too would just double-report it.
    return { allowed: true };
  }
  if (host === UNIVERSAL) return { allowed: true };
  if (typeof requestedModel !== 'string') return { allowed: true };

  const model = requestedModel.toLowerCase();
  for (const [family, hosts] of Object.entries(FAMILY_BINDINGS)) {
    if (!model.startsWith(family)) continue;
    const permitted = [...hosts, UNIVERSAL];
    return hosts.includes(host)
      ? { allowed: true, family, permitted }
      : { allowed: false, family, permitted };
  }
  // No rule for this namespace: permit. See "deliberately minimal" above.
  return { allowed: true };
}

/** Stable reason string for the receipt and the error report. */
export const BINDING_VIOLATION = 'upstream_not_bound_to_family';
