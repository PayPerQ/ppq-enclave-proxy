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
// the enclave has four exactly-pinned dependencies and a reproducible build, hp holds the
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
  'openai/': [
    'bedrock-mantle.us-east-1.api.aws',
    'bedrock-mantle.us-east-2.api.aws',
    // GPT-6 Astra is served from us-west-2 only (model card, probed
    // 2026-09-10); the other frontier models stay in the east regions.
    'bedrock-mantle.us-west-2.api.aws',
  ],
  // Google models go direct to Vertex.
  'google/': ['aiplatform.googleapis.com'],
  // Tinfoil TEE models go to Tinfoil's confidential router and nowhere else
  // (#210). OpenRouter is still "permitted" by the UNIVERSAL rule below, but
  // never reached: server.mjs strips the OpenRouter terminal from a private
  // candidate list before this check runs. Must equal TINFOIL_HOST in
  // tinfoil.mjs (a constant there for the same reason); a different router
  // is a measured change.
  'private/': ['inference.tinfoil.sh'],
  'venice/': ['api.venice.ai'],
});

/**
 * The form a model id is judged in: lower-cased, with OpenRouter's `~` alias
 * prefix (`~author/x-latest`, accepted by trace.mjs MODEL_RE and stripped by
 * webSearchTransforms.mjs modelNamespace) removed. Before this, `~anthropic/x`
 * matched no family and fell through to the permissive default below, so one
 * tilde turned the check off (Oct 17-19 security reports, Raju Arling Toni).
 */
export function bindingModelId(model) {
  return typeof model === 'string' ? model.toLowerCase().replace(/^~/, '') : model;
}

/**
 * Is this pairing of model id and upstream host permitted?
 *
 * @param {string} requestedModel a model id: the CLIENT's literal or hp's
 *        resolved id (see checkBindings for why both are judged), never the
 *        namespace-less wire id
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

  const model = bindingModelId(requestedModel);
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

/**
 * Judge a candidate host against EVERY id the request has carried: the string
 * the client sent and the id horse-power resolved it to.
 *
 * Judging only the resolved id made the check decorative against the party it
 * exists to constrain. hp supplies `resolved_model` in the same authorize
 * answer as the candidate list, so an hp that wanted `anthropic/x` served from
 * api.fireworks.ai could resolve it to `vendor/x` first and the family map
 * would match nothing (Oct 17-19 security reports: roolzer, Bron Zeee). The
 * client's literal is the one id hp does not author, so it is judged too; a
 * legitimate alias resolution (`claude-sonnet` -> `anthropic/claude-sonnet-5`)
 * passes because an id with no mapped namespace permits everything.
 *
 * Returns the first refusal, naming which id refused, else allowed.
 *
 * @param {Array<string|undefined|null>} ids
 * @param {string} host
 * @returns {{allowed: boolean, model?: string, family?: string, permitted?: string[]}}
 */
export function checkBindings(ids, host) {
  for (const id of ids) {
    const r = checkBinding(id, host);
    if (!r.allowed) return { ...r, model: id };
  }
  return { allowed: true };
}

/** Stable reason string for the receipt and the error report. */
export const BINDING_VIOLATION = 'upstream_not_bound_to_family';
