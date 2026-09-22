/**
 * Tinfoil (`private/*`) upstream — the in-enclave half of #210.
 *
 * WHY THE ENCLAVE SERVES THESE AT ALL
 * -----------------------------------
 * Every request for api.ppq.ai already terminates here, and every request that
 * is not chat bounces off to horse-power (passthrough.mjs). `/private/*` — the
 * Tinfoil TEE models — was one such bounce: horse-power relayed the client's
 * sealed body to Tinfoil's confidential router and billed from the router's
 * usage metrics. This module brings that relay into measured code and adds the
 * one thing horse-power could never offer: sealing on the caller's behalf.
 *
 * TWO CLASSES OF REQUEST, TOLD APART BY PATH
 * ------------------------------------------
 * Both carry `Ehbp-Encapsulated-Key`; only the path says which key the body
 * is sealed to, so the path is the discriminator and no header is sniffed.
 *
 *   A. `POST /private/v1/chat/completions` — the body is ALREADY sealed to
 *      Tinfoil's key by the client (ppq-private-mode, the Tinfoil SDK, the web
 *      app). The enclave cannot read it and does not try: it authorizes on the
 *      cleartext headers, relays the ciphertext, and bills from the router's
 *      trusted usage-metrics header/trailer. The plaintext exists only on the
 *      user's machine and inside Tinfoil's enclave — never here.
 *
 *   B. a `private/*` model on `POST /v1/chat/completions` — an ordinary
 *      (unsealed, or Nitro-sealed by a browser) request. The enclave verifies
 *      Tinfoil's SEV-SNP attestation ITSELF, seals the body to the attested
 *      HPKE key, forwards, and decrypts the reply. Plaintext exists here,
 *      briefly, inside measured code — the same guarantee every frontier model
 *      already has — and the ppq-private-mode proxy becomes optional.
 *
 * WHAT IS VERIFIED, AND OFFLINE
 * -----------------------------
 * `@tinfoilsh/verifier` checks the router's attestation report against the
 * VCEK carried in the bundle, the Sigstore provenance of the router release
 * against an EMBEDDED trusted root, and that the two measurements agree. Given
 * the bundle it makes no network call, so the only egress this adds is the
 * bundle fetch from `atc.tinfoil.sh` and the router itself — both through the
 * same pinned vsock tunnels every other upstream uses. Trusting horse-power's
 * `/private/.well-known/hpke-keys` instead would let hp substitute a key.
 *
 * NEVER OPENROUTER
 * ----------------
 * `normalizeCandidates` (upstreams.mjs) appends an OpenRouter terminal to
 * every candidate list so a request always has somewhere to fall. For a
 * private prompt that fall would be the leak the model exists to prevent.
 * `privateCandidates` strips the terminal; a private request that cannot
 * reach Tinfoil fails, it is not answered elsewhere.
 *
 * Wire format: the client half of ehbp 0.2 (the recipient half is
 * ehbp-server.mjs, built from the same primitives). Request: header
 * `Ehbp-Encapsulated-Key: <hex enc>`, body `[u32 BE len][HPKE seal]`. Response:
 * header `Ehbp-Response-Nonce: <hex 32B>`, frames `[u32 BE len][AES-GCM chunk]`
 * with the per-chunk nonce derived by OHTTP-style key schedule (derive.js).
 */

import https from 'node:https';
import { Transform } from 'node:stream';
import { CipherSuite } from 'hpke';
import {
  KEM_DHKEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM,
} from '@panva/hpke-noble';
import {
  deriveResponseKeys,
  decryptChunk,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  RESPONSE_NONCE_LENGTH,
} from 'ehbp';
import { Verifier } from '@tinfoilsh/verifier';

const enc = new TextEncoder();

/** hp's candidate name for Tinfoil's router; echoed on `provider` at settle. */
export const TINFOIL_PROVIDER = 'tinfoil';
/** The router release whose Sigstore provenance the attestation must match. */
export const TINFOIL_CONFIG_REPO = 'tinfoilsh/confidential-model-router';
/**
 * The confidential router every private/* request is relayed to or sealed
 * for. A CONSTANT, measured into PCR0, on purpose: hp's candidate names the
 * same host, upstreamBinding.mjs permits `private/` to reach only this host,
 * and the attestation bundle is fetched for exactly this name — three checks
 * that would silently disagree if any one of them read a different value.
 * Changing the router is a rotation, not a config change.
 */
export const TINFOIL_HOST = 'inference.tinfoil.sh';
/** Tinfoil's attestation service: builds the bundle for a named router. */
export const TINFOIL_ATC_HOST = 'atc.tinfoil.sh';
/** The router's trusted usage line: a header on JSON answers, a trailer on streams. */
export const USAGE_METRICS_HEADER = 'x-tinfoil-usage-metrics';
export const ENCAP_KEY_HEADER = 'ehbp-encapsulated-key';
export const RESPONSE_NONCE_HEADER = 'ehbp-response-nonce';
/** Settle `cost_source` for counts taken from the router's usage line. */
export const TINFOIL_COST_SOURCE = 'tinfoil-headers';
/** The client header naming the model on a sealed request (+ two legacy spellings). */
export const PRIVATE_MODEL_HEADERS = Object.freeze([
  'x-private-model',
  'x-encrypted-model',
  'x-tinfoil-model',
]);
export const DEFAULT_PRIVATE_MODEL = 'private/kimi-k3';

// Tinfoil answers a body sealed to a key it no longer holds (a router key
// rotation) with 422 and a problem+json body. The attestation is refetched
// once and the request rebuilt; a second 422 passes through.
export const KEY_CONFIG_MISMATCH_STATUS = 422;

/** How long a verified attestation is reused before it is fetched again. */
export const ATTESTATION_TTL_MS = 60 * 60 * 1000;

export function isPrivateModel(model) {
  return typeof model === 'string' && model.startsWith('private/');
}

/** The router's wire id: the `private/*` id without its prefix. */
export function routerModelId(model) {
  return typeof model === 'string' ? model.replace(/^private\//, '') : model;
}

export function isTinfoilCandidate(candidate) {
  return candidate?.provider === TINFOIL_PROVIDER;
}

export function hasTinfoilCandidate(candidates) {
  return Array.isArray(candidates) && candidates.some(isTinfoilCandidate);
}

/**
 * True when a private/* request arrived with NO Tinfoil candidate to serve it
 * — an older horse-power that still resolves private ids through its
 * OpenRouter table, or a resolution failure that fell back to the raw slug.
 * Without this the connector would take the OpenRouter terminal and ship a
 * private prompt to a provider the model exists to keep it from. The refusal
 * is the enclave's own rule, independent of what hp answered: it used to live
 * in routing.mjs as "use the Tinfoil path" and keeps that error code.
 */
export function refusesUnroutedPrivate(model, candidates) {
  return isPrivateModel(model) && !hasTinfoilCandidate(candidates);
}

/**
 * The converse: a Tinfoil candidate for a model that is NOT private/*. hp
 * never sends one, so this is a malformed or hostile authorize answer — and
 * following it would be provider substitution (a public model served, and
 * billed, as a Tinfoil one). Refused, not skipped: the private-only rule
 * below would also strip the OpenRouter terminal, leaving nothing sane.
 */
export function refusesMisroutedToTinfoil(model, candidates) {
  return !isPrivateModel(model) && hasTinfoilCandidate(candidates);
}

/**
 * The candidate list for a private request: Tinfoil only. Applied AFTER
 * normalizeCandidates, whose synthesised OpenRouter terminal must not survive
 * here — see NEVER OPENROUTER above.
 */
export function privateCandidates(candidates) {
  return (Array.isArray(candidates) ? candidates : []).filter(isTinfoilCandidate);
}

// ─── Usage metrics ──────────────────────────────────────────────────────────

/**
 * Parse the router's usage line, e.g.
 * `prompt=73,completion=12,total=85,cached_prompt_tokens=64,model=glm-5-3,cost_usd=0.00001815`.
 *
 * A port of horse-power's parseTinfoilUsageMetrics, with the same guards:
 * prompt/completion are required integers; `cached_prompt_tokens` must be a
 * CLEAN integer (a malformed value must not round down into a cache hit) and
 * is clamped to [0, prompt] (it is a subset of the prompt — if a router change
 * ever broke that, the bill degrades toward over-charge, never under). `model`
 * is the enclave-attested served model, the one billing must key on.
 * `cost_usd` is the router's own figure, carried for reconciliation only.
 *
 * Content-free by construction: every field is a number or a model id.
 */
export function parseUsageMetrics(metrics) {
  if (typeof metrics !== 'string' || metrics.length === 0 || metrics.length > 512) return null;
  const parts = {};
  for (const part of metrics.split(',')) {
    const idx = part.indexOf('=');
    if (idx > 0) parts[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  const promptTokens = parseInt(parts.prompt, 10);
  const completionTokens = parseInt(parts.completion, 10);
  if (!Number.isFinite(promptTokens) || !Number.isFinite(completionTokens)) return null;
  const total = parseInt(parts.total, 10);
  const cachedField = parts.cached_prompt_tokens;
  const cachedRaw =
    cachedField !== undefined && /^-?\d+$/.test(cachedField) ? Number(cachedField) : NaN;
  const cachedPromptTokens = Number.isSafeInteger(cachedRaw)
    ? Math.min(Math.max(0, cachedRaw), Math.max(0, promptTokens))
    : undefined;
  const cost = Number(parts.cost_usd);
  return {
    promptTokens: Math.max(0, promptTokens),
    completionTokens: Math.max(0, completionTokens),
    totalTokens: Number.isFinite(total) ? total : promptTokens + completionTokens,
    cachedPromptTokens,
    // Slug-shaped only, like every identifier that leaves the enclave.
    model: typeof parts.model === 'string' && /^[a-zA-Z0-9._:/@-]{1,96}$/.test(parts.model) ? parts.model : undefined,
    costUsd: Number.isFinite(cost) && cost >= 0 ? cost : undefined,
  };
}

/**
 * The usage line for a finished upstream response: the header on a JSON
 * answer, the trailer on a stream. `undefined` when the router sent neither.
 */
export function usageMetricsOf(upRes) {
  const h = upRes?.headers?.[USAGE_METRICS_HEADER];
  if (typeof h === 'string' && h) return h;
  const t = upRes?.trailers?.[USAGE_METRICS_HEADER];
  return typeof t === 'string' && t ? t : undefined;
}

// ─── Attestation ────────────────────────────────────────────────────────────

/** One HTTPS round trip over a vsock tunnel, JSON in and out. Rejects on any failure. */
function tunnelJson({ port, host, method, path, body, requestImpl = https.request, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const headers = { host, accept: 'application/json' };
    if (payload) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = payload.length;
    }
    const req = requestImpl(
      { host: '127.0.0.1', port, servername: host, method, path, headers, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`${host}${path}: HTTP ${res.statusCode}`));
          }
          try {
            resolve(JSON.parse(text));
          } catch (e) {
            reject(new Error(`${host}${path}: not JSON`));
          }
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`${host}${path}: timeout`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Fetch the attestation bundle for the PINNED router from ATC. A POST naming
 * the router, never the bare GET: the GET returns a bundle for a random
 * router in Tinfoil's fleet, whose key is not the pinned router's, and every
 * request sealed to it would be refused (horse-power learned this the hard
 * way — see tinfoil.controller.ts getAttestation).
 */
export function fetchTinfoilBundle({ atcPort, enclaveHost, requestImpl }) {
  return tunnelJson({
    port: atcPort,
    host: TINFOIL_ATC_HOST,
    method: 'POST',
    path: '/attestation',
    body: { enclaveUrl: `https://${enclaveHost}` },
    requestImpl,
  });
}

/** Shape-check a bundle before the verifier sees it, so a bad relay fails with a reason. */
export function validateBundleShape(bundle) {
  if (!bundle || typeof bundle !== 'object') throw new Error('attestation bundle is not an object');
  for (const f of ['domain', 'digest', 'vcek', 'enclaveCert']) {
    if (typeof bundle[f] !== 'string' || !bundle[f]) throw new Error(`attestation bundle: missing ${f}`);
  }
  if (!bundle.enclaveAttestationReport || typeof bundle.enclaveAttestationReport.body !== 'string') {
    throw new Error('attestation bundle: missing enclaveAttestationReport');
  }
  if (!bundle.sigstoreBundle || typeof bundle.sigstoreBundle !== 'object') {
    throw new Error('attestation bundle: missing sigstoreBundle');
  }
  return bundle;
}

/**
 * Verify a bundle and return the router's HPKE public key. Offline: the
 * verifier reads the VCEK from the bundle and carries its own Sigstore root.
 * `verifierImpl` is injectable so the schedule around it can be tested
 * without a real SEV-SNP report.
 */
export async function verifyTinfoilBundle(bundle, { enclaveHost, verifierImpl } = {}) {
  validateBundleShape(bundle);
  if (enclaveHost && bundle.domain !== enclaveHost) {
    // ATC answered for a different router than the one asked for. A key for
    // another router is useless (every request is refused) and a bundle for
    // another host is not the one the pin names.
    throw new Error(`attestation bundle is for ${bundle.domain}, expected ${enclaveHost}`);
  }
  const verifier = verifierImpl ? verifierImpl() : new Verifier({ configRepo: TINFOIL_CONFIG_REPO });
  const att = await verifier.verifyBundle({
    domain: bundle.domain,
    enclaveAttestationReport: bundle.enclaveAttestationReport,
    digest: bundle.digest,
    sigstoreBundle: bundle.sigstoreBundle,
    vcek: bundle.vcek,
    enclaveCert: bundle.enclaveCert,
  });
  const hpkePublicKeyHex = String(att?.hpkePublicKey || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hpkePublicKeyHex)) {
    throw new Error('verified attestation carries no 32-byte HPKE key');
  }
  return {
    hpkePublicKeyHex,
    measurement: att?.measurement?.registers?.[0] || '',
    domain: bundle.domain,
  };
}

/**
 * The verified-key cache. `get()` returns the current key, fetching and
 * verifying once per TTL (single-flight: concurrent first requests share one
 * fetch); `invalidate()` drops it so the next `get()` refetches (the 422
 * key-rotation path). `state()` is what /health shows: never the key itself,
 * only that a verification happened, when, and the measurement it matched.
 */
export function createTinfoilAttestor({
  enclaveHost,
  atcPort,
  log = () => {},
  fetchBundle = fetchTinfoilBundle,
  verify = verifyTinfoilBundle,
  ttlMs = ATTESTATION_TTL_MS,
  now = Date.now,
}) {
  let current = null; // { hpkePublicKeyHex, measurement, verifiedAt }
  let inflight = null;
  let lastError = null;

  async function refresh() {
    const bundle = await fetchBundle({ atcPort, enclaveHost });
    const v = await verify(bundle, { enclaveHost });
    current = { ...v, verifiedAt: now() };
    lastError = null;
    log(`tinfoil attestation verified for ${enclaveHost} (measurement ${current.measurement.slice(0, 16)}...)`);
    return current;
  }

  return {
    async get() {
      if (current && now() - current.verifiedAt < ttlMs) return current;
      if (!inflight) {
        inflight = refresh()
          .catch((e) => {
            lastError = e?.message || String(e);
            log(`tinfoil attestation FAILED: ${lastError}`);
            throw e;
          })
          .finally(() => {
            inflight = null;
          });
      }
      return inflight;
    },
    invalidate() {
      current = null;
    },
    state() {
      return {
        configured: Boolean(atcPort) && Boolean(enclaveHost),
        verified: Boolean(current),
        verified_at: current ? new Date(current.verifiedAt).toISOString() : null,
        measurement: current ? current.measurement : null,
        last_error: lastError ? 'failed' : null,
      };
    },
  };
}

// ─── Sealing (the client half of EHBP) ──────────────────────────────────────

function suite() {
  return new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
}

/**
 * Seal a request body to the router's HPKE public key. Returns the header
 * value, the framed body, and the material the response opener needs.
 * Mirrors ehbp's Identity.encryptRequestWithContext byte for byte.
 */
export async function sealForTinfoil(hpkePublicKeyHex, plaintext) {
  const s = suite();
  const publicKey = await s.DeserializePublicKey(new Uint8Array(Buffer.from(hpkePublicKeyHex, 'hex')));
  const { encapsulatedSecret, ctx } = await s.SetupSender(publicKey, { info: enc.encode(HPKE_REQUEST_INFO) });
  const sealed = await ctx.Seal(new Uint8Array(plaintext));
  const exportedSecret = new Uint8Array(await ctx.Export(enc.encode(EXPORT_LABEL), EXPORT_LENGTH));
  const body = Buffer.alloc(4 + sealed.byteLength);
  body.writeUInt32BE(sealed.byteLength, 0);
  Buffer.from(sealed).copy(body, 4);
  const requestEnc = new Uint8Array(encapsulatedSecret);
  return {
    encapHex: Buffer.from(requestEnc).toString('hex'),
    body,
    exportedSecret,
    requestEnc,
  };
}

/**
 * Open a sealed response frame by frame. `feed` returns the plaintext of every
 * COMPLETE frame in what has arrived so far (a frame can straddle chunks, and a
 * chunk can carry several); `finish` throws if bytes were left over, which is
 * a truncated frame — a response that ended mid-ciphertext, not a clean end.
 */
export async function createResponseOpener({ exportedSecret, requestEnc, responseNonceHex }) {
  if (typeof responseNonceHex !== 'string' || !/^[0-9a-f]+$/i.test(responseNonceHex)) {
    throw new Error(`missing or malformed ${RESPONSE_NONCE_HEADER}`);
  }
  const responseNonce = new Uint8Array(Buffer.from(responseNonceHex, 'hex'));
  if (responseNonce.length !== RESPONSE_NONCE_LENGTH) throw new Error('invalid response nonce length');
  const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);
  let buffer = Buffer.alloc(0);
  let seq = 0;
  return {
    async feed(chunk) {
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : Buffer.from(chunk);
      const out = [];
      while (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0);
        if (len === 0) {
          buffer = buffer.subarray(4);
          continue;
        }
        if (buffer.length < 4 + len) break;
        const ct = new Uint8Array(buffer.subarray(4, 4 + len));
        buffer = buffer.subarray(4 + len);
        out.push(Buffer.from(await decryptChunk(km, seq++, ct)));
      }
      return out.length === 1 ? out[0] : Buffer.concat(out);
    },
    finish() {
      if (buffer.length > 0) throw new Error(`sealed response truncated (${buffer.length} trailing bytes)`);
    },
    frames() {
      return seq;
    },
  };
}

/**
 * A readable of PLAINTEXT over a sealed upstream response, so the streaming
 * pipeline in server.mjs (cost extractor, rewriter, receipt, EHBP re-seal to a
 * browser) sees the same chat-completions bytes it sees from every other
 * upstream. Decryption is async, so the Transform serialises it; a frame that
 * fails to open errors the stream, which the caller treats like any upstream
 * stream failure. `upRes.trailers` is read by the caller at `end`, which fires
 * only after the upstream ended and the last frame was flushed.
 */
export function decryptedStream(upRes, opener) {
  const t = new Transform({
    transform(chunk, _enc, cb) {
      opener.feed(chunk).then(
        (plain) => cb(null, plain),
        (e) => cb(e),
      );
    },
    flush(cb) {
      try {
        opener.finish();
        cb();
      } catch (e) {
        cb(e);
      }
    },
  });
  upRes.on('error', (e) => t.destroy(e));
  return upRes.pipe(t);
}

// ─── Request builders ───────────────────────────────────────────────────────

// OpenRouter-only and PPQ-internal fields the router (an OpenAI-compatible
// surface) would not understand. Everything else is forwarded verbatim, as the
// ppq-private-mode proxy forwards it today: the router owns its own contract.
const NOT_FORWARDED = new Set([
  'provider',
  'plugins',
  'transforms',
  'route',
  'models',
  'usage',
  'query_source',
  'session_id',
  'chat_id',
  'tool_id',
  'zdr',
  'search_mode',
  'credit_id',
  'api_key',
  'data_source',
]);

/** The body sent to the router for a Class B request: the caller's, minus the fields above, model rewritten. */
export function projectForTinfoil(basePayload, upstreamModel) {
  const body = {};
  for (const [k, v] of Object.entries(basePayload || {})) {
    if (NOT_FORWARDED.has(k) || v === undefined) continue;
    body[k] = v;
  }
  body.model = upstreamModel;
  return body;
}

/** Upstream headers common to both classes. */
function routerHeaders({ host, key, bodyLength, encapHex, contentType }) {
  return {
    host,
    'content-type': contentType || 'application/json',
    'content-length': bodyLength,
    authorization: `Bearer ${key}`,
    // Ask for the usage line: a header on JSON answers, a trailer on streams.
    'x-tinfoil-request-usage-metrics': 'true',
    [ENCAP_KEY_HEADER]: encapHex,
    te: 'trailers',
  };
}

/**
 * Build the outbound request for a Class B candidate, sealing the projected
 * body to the router's verified key. `{skip}` when the enclave cannot use the
 * candidate; the caller has no other candidate to fall to for a private model
 * and answers accordingly.
 */
export async function buildTinfoilRequest({ candidate, basePayload, ports, keys, hpkePublicKeyHex }) {
  const port = ports?.[candidate.host];
  const key = keys?.[candidate.key_ref];
  if (!port || !key) return { skip: 'no_tunnel_or_key' };
  if (!hpkePublicKeyHex) return { skip: 'tinfoil_attestation_failed' };
  const body = projectForTinfoil(basePayload, candidate.upstream_model);
  const plaintext = Buffer.from(JSON.stringify(body));
  const sealed = await sealForTinfoil(hpkePublicKeyHex, plaintext);
  return {
    provider: TINFOIL_PROVIDER,
    apiStyle: 'tinfoil',
    orSlug: candidate.or_slug,
    upstreamModel: candidate.upstream_model,
    bodyStr: sealed.body,
    seal: { exportedSecret: sealed.exportedSecret, requestEnc: sealed.requestEnc },
    opts: {
      host: '127.0.0.1',
      port,
      servername: candidate.host,
      method: 'POST',
      path: candidate.path || '/v1/chat/completions',
      headers: routerHeaders({ host: candidate.host, key, bodyLength: sealed.body.length, encapHex: sealed.encapHex }),
    },
  };
}

/**
 * Upstream headers for a Class A relay: the client's encapsulated key and
 * content type travel through; the credential is REPLACED by the enclave's
 * Tinfoil key (the client's PPQ credential must never reach a third party).
 */
export function relayHeaders(reqHeaders, { host, key, bodyLength }) {
  const encap = reqHeaders?.[ENCAP_KEY_HEADER];
  const ct = reqHeaders?.['content-type'];
  return routerHeaders({
    host,
    key,
    bodyLength,
    encapHex: typeof encap === 'string' ? encap : '',
    contentType: typeof ct === 'string' && ct ? ct : 'application/json',
  });
}

/** The model a sealed request names, from its cleartext header (first spelling wins), else the default. */
export function claimedPrivateModel(reqHeaders) {
  for (const name of PRIVATE_MODEL_HEADERS) {
    const v = reqHeaders?.[name];
    if (typeof v === 'string' && v) return v;
  }
  return DEFAULT_PRIVATE_MODEL;
}

/**
 * Response headers a Class A relay hands back, mirroring horse-power's relay
 * so no client can tell the difference: the router's nonce and content type,
 * the usage line as a header when it came as one, else announced as a trailer
 * on a 200 stream (added at `end`).
 */
export function relayResponseHeaders(upRes) {
  const out = {};
  const nonce = upRes.headers[RESPONSE_NONCE_HEADER];
  if (typeof nonce === 'string') out['Ehbp-Response-Nonce'] = nonce;
  const ct = upRes.headers['content-type'];
  if (typeof ct === 'string') out['Content-Type'] = ct;
  const streaming = typeof ct === 'string' && ct.includes('text/event-stream');
  const usage = upRes.headers[USAGE_METRICS_HEADER];
  if (typeof usage === 'string' && usage) {
    out['X-Tinfoil-Usage-Metrics'] = usage;
  } else if (streaming && upRes.statusCode === 200) {
    out['Trailer'] = 'X-Tinfoil-Usage-Metrics';
  }
  return { headers: out, streaming };
}

/** A creator-payout tool id, in the one shape the payout path accepts, else null. */
export function toolIdOf(reqHeaders) {
  const v = reqHeaders?.['x-tool-id'];
  return typeof v === 'string' && /^[\w:.-]{1,64}$/.test(v) ? v : null;
}

/** The query source a sealed request declares: the closed set the settle path records. */
export function querySourceOf(reqHeaders) {
  const v = reqHeaders?.['x-query-source'];
  return v === 'ui' || v === 'memory' ? v : 'api';
}
