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

// ---------------------------------------------------------------------------
// Provider binding -- the OTHER half of what a candidate asserts.
//
// A candidate from /enclave/authorize names three things independently:
// `provider` (what the settle and the receipt will say served the request),
// `host` (which tunnel the bytes go down, and the name TLS is validated
// against) and `key_ref` (which provisioned secret goes in the Authorization
// header). checkBinding above ties the MODEL FAMILY to the host; nothing tied
// the three candidate fields to each other. So a candidate reading
// `{ provider: 'fireworks', host: 'api.venice.ai', key_ref: 'openrouter' }`
// was built, sent PayPerQ's OpenRouter key to Venice, and settled as Fireworks
// (Oct 17-19 security reports: bgsparsiti finding 2, bronzeee F2; both
// reproduced locally against the real server with stand-in hosts).
//
// Reachable hosts are already limited to UPSTREAM_PORTS, so a key can only
// ever be misdirected to one of PayPerQ's own providers, never an attacker's
// host -- this is credential hygiene and settle integrity, not exfiltration.
// It still should not be possible, and it is one more thing the enclave
// decides for itself rather than taking hp's word for.
//
// Each provider the enclave can serve already has exactly one key and a
// closed set of tunnels, both measured into the image, so unlike the family
// map this table IS complete: a provider name it does not list is one the
// enclave has no secret for, and such a candidate is refused rather than
// permitted (the family map's "absent rule permits" rationale does not apply
// -- there is no legitimate traffic it could break).
//
// FAIL-SAFE, like checkBinding: a violating candidate is SKIPPED with a stable
// reason, never fatal; the OpenRouter terminal still serves the request.
// ---------------------------------------------------------------------------

/**
 * Provider -> the hosts it may be reached at, and the one key_ref whose
 * secret may be presented to it. Hosts must match UPSTREAM_PORTS in
 * server.mjs (a host with no tunnel is dead anyway, see the reachability
 * test); key_refs match UPSTREAM_KEYS / the bedrock and vertex holders.
 */
export const PROVIDER_BINDINGS = Object.freeze({
  openrouter: Object.freeze({ hosts: Object.freeze(['openrouter.ai']), key_ref: 'openrouter' }),
  fireworks: Object.freeze({ hosts: Object.freeze(['api.fireworks.ai']), key_ref: 'fireworks' }),
  // Fireworks' stack behind an Azure resource hostname (upstreams.mjs
  // FOUNDRY_HOST); a different secret, so a different binding.
  foundry: Object.freeze({
    hosts: Object.freeze(['ppq-foundry.services.ai.azure.com']),
    key_ref: 'foundry',
  }),
  venice: Object.freeze({ hosts: Object.freeze(['api.venice.ai']), key_ref: 'venice' }),
  anthropic: Object.freeze({ hosts: Object.freeze(['api.anthropic.com']), key_ref: 'anthropic' }),
  // SigV4 with the host-delivered STS credentials (bedrock.mjs reads the
  // holder, not UPSTREAM_KEYS); hp still names the ref, so it is still bound.
  bedrock: Object.freeze({
    hosts: Object.freeze([
      'bedrock-mantle.us-east-1.api.aws',
      'bedrock-mantle.us-east-2.api.aws',
      'bedrock-mantle.us-west-2.api.aws',
    ]),
    key_ref: 'bedrock',
  }),
  // The minted OAuth token (vertexAuth.mjs), resolved under this ref. Only the
  // global host has a tunnel; a regional `<loc>-aiplatform.googleapis.com`
  // candidate would be skipped for want of a port before reaching here.
  vertex: Object.freeze({ hosts: Object.freeze(['aiplatform.googleapis.com']), key_ref: 'vertex' }),
  // Must equal TINFOIL_HOST in tinfoil.mjs (and the 'private/' family above).
  tinfoil: Object.freeze({ hosts: Object.freeze(['inference.tinfoil.sh']), key_ref: 'tinfoil' }),
});

/** Stable skip reasons for the trace and the error report. */
export const PROVIDER_UNKNOWN = 'provider_unknown';
export const PROVIDER_HOST_MISMATCH = 'provider_host_mismatch';
export const PROVIDER_KEY_MISMATCH = 'provider_key_mismatch';

/**
 * Do this candidate's provider, host and key_ref agree?
 *
 * `host` may be absent on a legacy (pre-host-keyed) candidate: the builder
 * then picks the tunnel by provider name, which is bound by construction, so
 * only the key_ref is judged. An absent key_ref is a mismatch: every provider
 * here needs a credential, and "no ref" would otherwise let the builder's
 * `keys[undefined]` lookup decide.
 *
 * @param {{provider?: string, host?: string, key_ref?: string}} candidate
 * @returns {{allowed: boolean, reason?: string, field?: string, expected?: object}}
 */
export function checkProviderBinding(candidate) {
  const provider = candidate?.provider;
  const rule = typeof provider === 'string' ? PROVIDER_BINDINGS[provider] : undefined;
  if (!rule) return { allowed: false, reason: PROVIDER_UNKNOWN, field: String(provider) };
  const host = candidate?.host;
  if (typeof host === 'string' && host.length > 0 && !rule.hosts.includes(host)) {
    return { allowed: false, reason: PROVIDER_HOST_MISMATCH, field: host, expected: rule };
  }
  if (candidate?.key_ref !== rule.key_ref) {
    return {
      allowed: false,
      reason: PROVIDER_KEY_MISMATCH,
      field: String(candidate?.key_ref),
      expected: rule,
    };
  }
  return { allowed: true };
}
