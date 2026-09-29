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
import https from 'node:https';
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
 * and this assignment is the only writer. Web search is not wired on this path;
 * if it ever is, its keys join THIS object rather than a second assignment,
 * because `venice_parameters` is one JSON member and a later whole-object
 * assignment would silently drop the flag.
 */
function applyVeniceParameters(body, candidate) {
  if (candidate?.provider !== 'venice' && candidate?.host !== 'api.venice.ai') return;
  body.venice_parameters = { include_venice_system_prompt: false };
}

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
  applyVeniceParameters(body, candidate);
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

/**
 * A fetch-shaped function for the PII detector (pii/detector.mjs), reaching it
 * through its vsock tunnel: connect to 127.0.0.1:<port> and validate TLS
 * against the REAL hostname, so the parent forwards bytes it cannot read and
 * cannot redirect them — a misdirected tunnel fails the handshake. The same
 * shape as createAcmeFetch (acmeTransport.mjs), plus the one thing the detector
 * needs and ACME does not: `init.signal` aborts the request, so the detector's
 * timeout actually stops waiting. In production the body arrives here already
 * sealed to the detector's attested key (pii/attestedDetector.mjs), so TLS is
 * the outer layer, not the trust anchor; nothing here logs it either way.
 * `headers.get` and `arrayBuffer` expose the sealed reply's nonce and frames.
 *
 * @param {{tunnels: Record<string, number>}} opts hostname -> loopback port
 */
export function createTunnelFetch({ tunnels }) {
  return function tunnelFetch(url, init = {}) {
    const u = new URL(url);
    const port = tunnels?.[u.hostname];
    if (u.protocol !== 'https:' || !port) return Promise.reject(new Error('no tunnel for this host'));
    if (init.signal?.aborted) return Promise.reject(new Error('aborted'));
    const body = init.body ? Buffer.from(init.body) : null;
    const headers = { ...(init.headers || {}), host: u.hostname };
    if (body) headers['content-length'] = body.length;
    return new Promise((resolve, reject) => {
      const req = https.request(
        { host: '127.0.0.1', port, servername: u.hostname, method: init.method || 'GET', path: u.pathname + u.search, headers },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const raw = Buffer.concat(chunks);
            const text = raw.toString('utf8');
            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
              arrayBuffer: async () => raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.length),
              text: async () => text,
              json: async () => JSON.parse(text),
            });
          });
          res.on('error', reject);
        },
      );
      const onAbort = () => req.destroy(new Error('aborted'));
      init.signal?.addEventListener?.('abort', onAbort, { once: true });
      req.on('close', () => init.signal?.removeEventListener?.('abort', onAbort));
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  };
}
