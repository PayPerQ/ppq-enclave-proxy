/**
 * PPQ Enclave Proxy — trusted core
 *
 * Runs INSIDE an AWS Nitro Enclave. Terminates the client's TLS connection here
 * (the parent EC2 instance only ever forwards ciphertext over vsock), forwards
 * chat-completion requests to OpenRouter, streams the response back, extracts
 * usage/cost from the stream, and reports ONLY billing metadata to horse-power.
 *
 * The parent instance and PayPerQ never see decrypted query/response content.
 *
 * Networking (all TCP tunnelled over vsock by socat/vsock-proxy on the host):
 *   inbound   127.0.0.1:INBOUND_PORT   <- client (TLS terminates here)
 *   openrouter 127.0.0.1:OR_PORT       -> host vsock-proxy -> openrouter.ai:443
 *   settle     127.0.0.1:SETTLE_PORT   -> host vsock-proxy -> <horse-power host>:443
 *
 * TLS to OpenRouter and horse-power is still validated end-to-end against their
 * real hostnames (servername + default CA checks); the local socket is just the
 * mouth of the vsock tunnel.
 */

import https from 'node:https';
import cluster from 'node:cluster';
import { readFileSync } from 'node:fs';
import { X509Certificate, createHash, createPrivateKey, randomUUID, timingSafeEqual } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  resolveModel,
  transformPayload,
  applySafetyIdentifier,
  applyFreeModelStrip,
  applyAutoRouterConfig,
  parseAutoRouter,
  applyToolStrip,
} from './routing.mjs';
import { refusesUnauthorizedFree } from './eligibility.mjs';
import { createSettleQueue, classifySettleStatus } from './settleQueue.mjs';
import {
  ERROR_CODES,
  buildErrorReport,
  classifyModelRejection,
} from './errorReport.mjs';
import { CostExtractor } from './cost.mjs';
import { Rebrander, directResponseRewriter } from './rebrand.mjs';
import { buildReceipt, signedReceiptBytes } from './receipt.mjs';
import { keySources } from './keySources.mjs';
import {
  kmstoolBackend, leafValidity, loadCachedCertificate, saveSealedBlob, sealStore,
  selfTest, storeCredsFromEnv,
} from './acmeStore.mjs';
import { hasWebSearch } from './webSearchTransforms.mjs';
import { BINDING_VIOLATION, checkBinding } from './upstreamBinding.mjs';
import {
  challengeCredentials,
  hasPendingChallenge,
  issuedCredentials,
  issuedSigningKey,
  issuedCertificateEntries,
  issuedCertificateSummary,
  obtainCertificate,
  selectAlpn,
  setIssuedCertificate,
  setPendingChallenge,
  beginRenewalCsr,
  completeRenewal,
} from './acmeRunner.mjs';
import { createAcmeFetch } from './acmeTransport.mjs';
import { buildDirectRequest, isOpenRouter, normalizeCandidates } from './upstreams.mjs';
import { buildBedrockRequest, ResponsesToChatSse } from './bedrock.mjs';
import { buildAnthropicRequest, MessagesToChatSse } from './anthropic.mjs';
import { BedrockCredsHolder } from './bedrockCreds.mjs';
import { VertexTokenMinter } from './vertexAuth.mjs';
import { resolveHpkeIdentity } from './hpkeIdentity.mjs';
import { EhbpRecipient } from './ehbp-server.mjs';
import { MSG, isMessage, workerCount } from './clusterProto.mjs';

const execFileAsync = promisify(execFile);

const cfg = {
  inboundPort: Number(process.env.INBOUND_PORT || 8443),
  orPort: Number(process.env.OR_PORT || 9443),
  settlePort: Number(process.env.SETTLE_PORT || 9444),
  orHost: process.env.OPENROUTER_HOST || 'openrouter.ai',
  settleHost: process.env.SETTLE_HOST, // e.g. abc123.ngrok-free.dev
  settleSecret: process.env.ENCLAVE_SETTLE_SECRET || '',
  safetySecret: process.env.SAFETY_IDENTIFIER_SECRET || '',
  tlsKeyPath: process.env.TLS_KEY_PATH || '/app/tls/key.pem',
  tlsCertPath: process.env.TLS_CERT_PATH || '/app/tls/cert.pem',
};

// The OpenRouter API key is injected at boot by boot.sh after an
// attestation-gated KMS Decrypt. It never touches disk on the parent.
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

// Phase 1b/2: per-upstream vsock tunnel ports + provisioned keys. hp's
// /authorize candidate list names an upstream by `host` (tunnel port) +
// `key_ref` (which secret). The port map is keyed by HOST because a provider
// can have per-region hosts (Bedrock); the provider-name keys remain as a
// fallback for one release of older hp candidate payloads. An upstream with no
// port or no key/creds here is simply skipped, so the request falls back to
// OpenRouter — bedrock stays inert until boot.sh provisions the tunnels and
// the host delivers signing creds.
const UPSTREAM_PORTS = {
  'openrouter.ai': cfg.orPort,
  'api.fireworks.ai': Number(process.env.FIREWORKS_PORT || 0),
  'bedrock-mantle.us-east-2.api.aws': Number(process.env.BEDROCK_USE2_PORT || 0),
  'bedrock-mantle.us-east-1.api.aws': Number(process.env.BEDROCK_USE1_PORT || 0),
  'api.anthropic.com': Number(process.env.ANTHROPIC_PORT || 0),
  'aiplatform.googleapis.com': Number(process.env.VERTEX_PORT || 0),
  // Legacy provider-name fallback (pre-host-keyed hp payloads).
  openrouter: cfg.orPort,
  fireworks: Number(process.env.FIREWORKS_PORT || 0),
};
const UPSTREAM_KEYS = {
  openrouter: OPENROUTER_API_KEY,
  fireworks: process.env.FIREWORKS_API_KEY || '',
  anthropic: process.env.ANTHROPIC_API_KEY || '',
};

// Bedrock SigV4 credentials: short-lived STS creds the host re-delivers over
// vsock:7001 (boot.sh forwards it to the loopback listener started in start()).
// key_ref 'bedrock' resolves to this holder, not UPSTREAM_KEYS.
const bedrockCreds = new BedrockCredsHolder({
  kmsPort: Number(process.env.KMS_PORT || 8000),
  log,
});

// Vertex OAuth minting (key_ref 'vertex'): the SA key never goes on the wire —
// vertexAuth.mjs mints short-lived access tokens through the oauth tunnel.
// Inert (candidates skip to OpenRouter) until boot.sh provisions the key AND
// the host runs both Google tunnels.
const vertexMinter = new VertexTokenMinter({
  saKeyJson: process.env.VERTEX_SA_KEY_JSON || '',
  oauthPort: Number(process.env.GOOGLE_OAUTH_PORT || 0),
  log,
});

/**
 * Fire one upstream request and resolve when the RESPONSE HEADERS arrive —
 * WITHOUT consuming the body — so the caller can inspect the status and either
 * stream it or fall back to the next candidate. Never rejects.
 */
function attemptUpstream(opts, bodyStr) {
  return new Promise((resolve) => {
    const r = https.request(opts, (res) => {
      const code = res.statusCode || 0;
      resolve({ ok: code >= 200 && code < 300, statusCode: code, res });
    });
    r.on('error', (e) => resolve({ ok: false, error: e }));
    r.write(bodyStr);
    r.end();
  });
}

// SHA-256 of this enclave's TLS certificate SubjectPublicKeyInfo (DER). The
// attestation commits to this in `user_data`, letting a programmatic client that
// terminates TLS at the enclave pin the TLS endpoint to this attested enclave.
let CERT_SPKI_SHA256_HEX = '';
// Kept so routing receipts can be SIGNED with the key the attestation already
// commits to (user_data = SHA-256 of this cert's SPKI). Generated in-enclave by
// boot.sh and never written anywhere the parent can read, so a signature by it
// is a statement only the measured enclave can make. See receipt.mjs.
let TLS_PRIVATE_KEY = null;
// The SPKI itself, base64 DER, returned by /attestation so a BROWSER can verify
// a signature: JS cannot read a TLS peer certificate, so without this a page
// could check the attestation and still have no key to verify against. The host
// cannot substitute it -- the client hashes it and compares to user_data inside
// the NSM-signed document.
let CERT_SPKI_DER_B64 = '';

/**
 * Outcome of the boot-time sealed-store round-trip, surfaced on /health.
 *
 * `absent` until the check runs, which is also the honest answer when the store
 * is unconfigured — this ships inert, exactly as in-enclave ACME did in v0.7.0.
 */
let acmeStoreSelfTest = 'absent';

// EHBP recipient (HPKE keypair). Browsers HPKE-seal their request body to this
// public key, which the attestation commits to in `public_key`. Only the enclave
// holds the private key, so the host — even terminating the browser's TLS — sees
// only ciphertext.
//
// Unsealed from the certificate store when it holds one, generated only when it
// does not (#52 scaling). A browser attests on one connection and seals on the
// next, so the key must be the same across restarts — and, once there is more
// than one box, across boxes. `hpke_identity` on /health says which happened;
// anything but `store` after the first boot is a regression.
let ehbpRecipient = null;
let HPKE_PUBLIC_KEY_HEX = '';
let hpkeIdentitySource = 'unset';
// null until known: true once the identity has been handed to the parent's
// save channel (or came from the store), false when this process could not or
// must not put it there (so the next restart WILL rotate it). The channel has
// no acknowledgement -- a parent-side write failure after the stream closed
// would not be seen here; see #52 for the follow-up.
let hpkeIdentityPersisted = null;

// In-enclave cluster (#52 scaling, step 5). 1 = one process, the behaviour
// before this existed. See clusterProto.mjs for what crosses IPC and why.
const WORKER_COUNT = workerCount(process.env);

// Certificate renewal in a fleet (#52 scaling, DNS-01). Behind a load
// balancer the TLS-ALPN-01 validating handshake lands on a random box, so:
//   ACME_RENEWAL_AUTHORITY  '1' on exactly ONE box (the build host); every
//                           other box never orders and takes the next sealed
//                           store from S3.
//   ACME_RENEWAL_MODE       'alpn' (in-enclave order, the single-box path) or
//                           'dns01-ci' (CI proves the domain with a DNS record;
//                           this box hands CI a CSR over an in-enclave key via
//                           POST /acme/csr and installs the result via
//                           POST /acme/install -- the key never leaves).
//   ACME_CI_TOKEN           bearer token those two routes require; without it
//                           they do not exist (404), token or not.
const ACME_RENEWAL_MODE = process.env.ACME_RENEWAL_MODE || 'alpn';
const ACME_RENEWAL_AUTHORITY = (process.env.ACME_RENEWAL_AUTHORITY ?? '1') === '1';
const ACME_CI_TOKEN = process.env.ACME_CI_TOKEN || '';
// What start() decided about ACME, for the renewal routes and the RPC.
let acmeCtx = null;

/** Hex-encode a client nonce safely (reject anything non-hex, cap length). */
function sanitizeNonceHex(v) {
  if (typeof v !== 'string') return '';
  const s = v.toLowerCase();
  if (!/^[0-9a-f]{0,128}$/.test(s) || s.length % 2 !== 0) return '';
  return s;
}

function log(...a) {
  // Structured, content-free logging only. NEVER log messages/prompts.
  console.log(JSON.stringify({ t: new Date().toISOString(), msg: a.join(' ') }));
}

function readRawBody(req, limitBytes = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(body);
}

/**
 * Authorize the caller with horse-power BEFORE spending the company OpenRouter
 * key. Forwards only the cleartext auth headers + model (never query content).
 * horse-power validates the API key / credit_id and checks balance, and returns
 * the resolved credit_id + api_key_id used for settlement. Resolves to
 * { ok, status, body, credit_id, api_key_id }.
 */
function authorizeWithHorsepower(reqHeaders, model, maxTokens, inputBytes) {
  return new Promise((resolve) => {
    if (!cfg.settleHost) {
      // No horse-power reachable — fail closed, do not spend the key.
      return resolve({ ok: false, status: 503, body: { error: 'authorization unavailable' } });
    }
    // input_bytes lets hp bound the INPUT cost of a browser-generated title.
    // Capping only the output would bound the wrong half of the bill: a forged
    // title with a huge prompt is cheap per output token and expensive per input
    // token. A byte count, not a token count — a pinned build cannot carry a
    // tokenizer, and hp only needs an upper bound.
    const payload = JSON.stringify({
      model,
      max_tokens: maxTokens,
      input_bytes: Number.isFinite(inputBytes) ? inputBytes : undefined,
    });
    const headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
      host: cfg.settleHost,
    };
    if (reqHeaders['authorization']) headers['authorization'] = reqHeaders['authorization'];
    if (reqHeaders['x-credit-id']) headers['x-credit-id'] = reqHeaders['x-credit-id'];
    if (reqHeaders['x-query-source']) headers['x-query-source'] = reqHeaders['x-query-source'];
    // Lets the browser declare a conversation-title request so hp can bill it to
    // PayPerQ rather than the user (horse-power titleIntent.ts). Forwarded, not
    // interpreted: hp caps the model and output length, which is what makes the
    // header safe to accept from a client. Without this the title could not ride
    // the attested transport, and titling would keep sending the user's opening
    // message to a PayPerQ server in the clear.
    if (reqHeaders['x-ppq-intent']) headers['x-ppq-intent'] = reqHeaders['x-ppq-intent'];

    const r = https.request(
      {
        host: '127.0.0.1',
        port: cfg.settlePort,
        servername: cfg.settleHost,
        method: 'POST',
        path: '/enclave/authorize',
        headers,
      },
      (resp) => {
        let b = '';
        resp.on('data', (d) => (b += d));
        resp.on('end', () => {
          let body = {};
          try { body = JSON.parse(b || '{}'); } catch { /* leave {} */ }
          const ok = resp.statusCode === 200 && body.authorized === true;
          resolve({
            ok,
            status: resp.statusCode || 502,
            body,
            credit_id: body.credit_id,
            api_key_id: body.api_key_id ?? null,
            // Model identity resolved by hp against the live catalog (#2). May be
            // absent on older hp — callers fall back to the raw model.
            resolved_model: body.resolved_model,
            provider_directive: body.provider_directive ?? null,
            // Catalog-dependent payload directives hp decides but the enclave
            // applies (#6). Absent on older hp → default false (no strip).
            strip_tools: body.strip_tools === true,
            is_free: body.is_free === true,
            // PPQ's Auto Router allow-list (#790). Absent on older hp → null,
            // and applyAutoRouterConfig injects nothing. Shape-checked rather
            // than passed through: a malformed body must not become a plugin
            // OpenRouter rejects, and a missing allow-list is safer than a
            // half-formed one.
            auto_router: parseAutoRouter(body.auto_router),
            // Ordered upstream candidate list (Phase 1). Absent on older hp →
            // empty, and the connector falls back to OpenRouter-only.
            upstreams: Array.isArray(body.upstreams) ? body.upstreams : [],
            // How many output tokens the caller's balance can still pay for
            // after the input (billing hardening, 2026-09-10). Applied as
            // max_tokens = min(requested, cap) below. Absent/null on older hp
            // and on free or unpriced models → no cap.
            max_tokens_cap:
              Number.isInteger(body.max_tokens_cap) && body.max_tokens_cap > 0
                ? body.max_tokens_cap
                : null,
          });
        });
      },
    );
    r.on('error', (e) => {
      log(`authorize error: ${e.message}`);
      resolve({ ok: false, status: 502, body: { error: 'authorization failed' } });
    });
    r.write(payload);
    r.end();
  });
}

/** One settlement POST attempt → resolves 'ok' | 'permanent' | 'transient'. */
function settlePostOnce(meta) {
  return new Promise((resolve) => {
    if (!cfg.settleHost) return resolve('permanent');
    const payload = JSON.stringify(meta);
    const opts = {
      host: '127.0.0.1',
      port: cfg.settlePort,
      servername: cfg.settleHost, // validate TLS against the real horse-power host
      method: 'POST',
      path: '/enclave/settle',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-enclave-secret': cfg.settleSecret,
        host: cfg.settleHost,
      },
    };
    const r = https.request(opts, (resp) => {
      resp.resume(); // drain the body; we only need the status
      resp.on('end', () => {
        const outcome = classifySettleStatus(resp.statusCode || 0);
        log(`settle status=${resp.statusCode} req=${meta.request_id} -> ${outcome}`);
        resolve(outcome);
      });
    });
    r.setTimeout(15_000, () => r.destroy(new Error('settle timeout')));
    r.on('error', (e) => {
      log(`settle error req=${meta.request_id}: ${e.message}`);
      resolve('transient');
    });
    r.write(payload);
    r.end();
  });
}

// Durable retry queue: submit() tries once, then retries transient failures with
// exponential backoff until horse-power acks. Settlement is idempotent, so a
// retry after a slow/lost success is a harmless no-op. See settleQueue.mjs.
const settleQueue = createSettleQueue({ post: settlePostOnce, log });

/**
 * Fire-and-forget failure report (horse-power#800).
 *
 * Deliberately NOT on the durable settle queue. A dropped settlement is a
 * revenue leak, so that queue retries until acked; a dropped error report is
 * just a missing log line, and putting best-effort traffic through the
 * revenue-critical path risks starving it during exactly the upstream outage
 * that is generating the reports.
 *
 * Never throws and never awaited: reporting a failure must not become a second
 * failure, and must not delay the response the caller is already owed.
 */
function reportEnclaveError(code, fields = {}) {
  if (!cfg.settleHost) return;
  const body = buildErrorReport(code, fields);
  if (!body) {
    log(`error report skipped: unknown code`);
    return;
  }
  try {
    const payload = JSON.stringify(body);
    const r = https.request(
      {
        host: '127.0.0.1',
        port: cfg.settlePort,
        servername: cfg.settleHost,
        method: 'POST',
        path: '/enclave/error',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
          'x-enclave-secret': cfg.settleSecret,
          host: cfg.settleHost,
        },
      },
      (resp) => resp.resume(),
    );
    r.setTimeout(5_000, () => r.destroy());
    // setTimeout only fires on socket INACTIVITY, so a trickle of response
    // bytes would hold this open indefinitely — and these fire during upstream
    // outages, exactly when sockets pile up. Independent hard deadline.
    const deadline = setTimeout(() => r.destroy(), 5_000);
    r.on('close', () => clearTimeout(deadline));
    r.on('error', (e) => log(`error report failed: ${e.message}`));
    r.write(payload);
    r.end();
  } catch (e) {
    log(`error report threw: ${e.message}`);
  }
}

/** Fire-and-forget settlement — durable: retried on transient failure (#5). */
function reportSettlement(meta) {
  if (!cfg.settleHost) {
    log('settle skipped: SETTLE_HOST unset');
    return;
  }
  settleQueue.submit(meta);
}

async function handleChatCompletion(req, res) {
  // The CLIENT's correlation id: echoed on receipts, error reports and the
  // metadata row (the frontend looks a column's price up by it). It is NOT the
  // billing idempotency key — it was, and a caller who reused one header value
  // got every request after the first served and never billed (proved live
  // 2026-09-10). The key hp claims is `settleId`, minted here per request.
  const requestId =
    req.headers['x-request-id'] ||
    `enc-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const settleId = randomUUID();

  // Auth material travels in cleartext headers (never the body).
  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'];
  if (!creditId && !authHeader) {
    return sendJson(res, 401, {
      error: { message: 'Missing x-credit-id or Authorization', code: 401 },
    });
  }

  // Read the body. If the browser used EHBP (Ehbp-Encapsulated-Key header), the
  // body is HPKE-sealed to our key — decrypt it here, inside the enclave. Keep
  // the HPKE context so we can encrypt the response back to the same client.
  let payload;
  let ehbpCtx = null;
  try {
    const rawBody = await readRawBody(req);
    const encapKey = req.headers['ehbp-encapsulated-key'];
    if (encapKey) {
      if (!ehbpRecipient) throw new Error('EHBP not initialised');
      const opened = await ehbpRecipient.openRequest(String(encapKey), rawBody);
      payload = JSON.parse(opened.plaintext.toString('utf8'));
      ehbpCtx = { exportedSecret: opened.exportedSecret, requestEnc: opened.requestEnc };
    } else {
      payload = JSON.parse(rawBody.toString('utf8'));
    }
  } catch (e) {
    // e.message stays in log() — it can quote the body it failed to parse.
    log(`request unreadable: ${e.message}`);
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      query_source: req.headers['x-query-source'] === 'ui' ? 'ui' : 'api',
    });
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }

  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  // Enclave-local resolution first: object->string + reject unsupported models.
  // (Full slug/alias resolution can't happen here — it needs the live catalog a
  // pinned build can't hold — so hp does it at /authorize below.)
  try {
    resolveModel(payload);
  } catch (e) {
    log(`model rejected: ${e.message}`);
    // Reports WHY, not WHICH. `payload.model` here is straight out of the
    // decrypted body and nothing has proved it is a catalog value, so echoing
    // it would put caller-controlled text into our logs and Sentry tags.
    reportEnclaveError(classifyModelRejection(e.message), {
      request_id: requestId,
      query_source: querySource,
    });
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }

  // Gate on horse-power authorization BEFORE spending the company key. This
  // authenticates the caller (API key or credit_id) and checks balance; without
  // it, anyone reaching the enclave could get free inference on the shared key.
  // It ALSO returns the resolved upstream model slug (+ derived provider pin),
  // so we authorize BEFORE transformPayload and apply the resolution below (#2).
  const auth = await authorizeWithHorsepower(
    req.headers,
    payload.model,
    payload.max_tokens ?? payload.max_completion_tokens,
    // Size of the messages we are about to forward. Cheap to compute and it is
    // only ever an upper bound for a spend cap, never billing input.
    (() => {
      try {
        return JSON.stringify(payload.messages ?? []).length;
      } catch {
        return undefined;
      }
    })(),
  );
  if (!auth.ok) {
    // No model: the only value available here is the raw body's, hp has not
    // canonicalized it yet, and hp already knows which model it just refused.
    // (It is also not the `model` const — that is declared below, so naming it
    // here would be a temporal dead zone ReferenceError on every
    // insufficient-credit request.)
    reportEnclaveError(ERROR_CODES.AUTHORIZE_REJECTED, {
      request_id: requestId,
      upstream_status: auth.status,
      query_source: querySource,
    });
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    });
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;

  // Apply hp's model resolution (#2) to the neutral payload. Falls back to the
  // raw model when hp didn't resolve it (older hp). Applies to BOTH paths.
  const modelResolvedByHp =
    typeof auth.resolved_model === 'string' && !!auth.resolved_model;
  if (modelResolvedByHp) {
    payload.model = auth.resolved_model;
  }
  const model = payload.model;
  // Only a slug hp resolved against the live catalog is safe to report. When hp
  // does not resolve (older build), `model` is still the raw string from the
  // decrypted body — caller-controlled text that has proved nothing about
  // itself, and slug syntax is not a content boundary (`my-password-is-x`
  // passes any such regex). hp re-checks against its catalog too; this keeps
  // the enclave side airtight regardless.
  const reportableModel = modelResolvedByHp ? model : undefined;
  // Billing follows hp's directive, NOT a slug pattern. This was the last
  // survivor of the local `:free` heuristic that routing.mjs already warns
  // about: the plugin/tool strip was moved onto `auth.is_free` so there would be
  // one source of truth, but the cost side kept matching on the string and so
  // still disagreed with hp.
  //
  // The two disagree in both directions. hp's isFree is an exact-slug list
  // (`ppq/free`, `openrouter/free`), so a concrete OpenRouter free variant such
  // as `cohere/north-mini-code:free` — which hp bills normally — matched the
  // regex here and zeroed the charge. In the other direction any paid slug
  // ending in "free" would have been given away. Neither is hypothetical now
  // that free models actually route here (PPQdotAI: free models ride the
  // enclave); before that this code path took no free traffic at all.
  const isFreeModel = auth.is_free === true;

  // Fail closed on the free aliases: without hp's is_free directive this would
  // be served on the PAID path, keeping any `web` plugin the caller attached and
  // billing PPQ for it on a request that must cost $0. See
  // refusesUnauthorizedFree for why `modelResolvedByHp` cannot catch this.
  // Refusing sends the client back to the normal path, which resolves free
  // models correctly.
  if (refusesUnauthorizedFree(model, auth.is_free)) {
    reportEnclaveError(ERROR_CODES.FREE_MODEL_UNAUTHORIZED, {
      request_id: requestId,
      credit_id: billedCreditId,
      model: reportableModel,
      query_source: querySource,
    });
    return sendJson(res, 400, {
      error: { message: 'free model unavailable on this path', code: 400 },
    });
  }

  // Spend cap (billing hardening, 2026-09-10). hp's pre-flight estimate assumes
  // a default output length when the caller sends no max_tokens, but nothing
  // enforced that assumption upstream: the model could generate far more, the
  // debit floor would then reject the settle, and the answer had already gone
  // out. So the request can never ASK for more output than the balance pays
  // for. Applied before the snapshot so both the direct and OpenRouter bodies
  // carry it; max_completion_tokens is the same knob under its newer name.
  if (auth.max_tokens_cap) {
    const requested = payload.max_tokens ?? payload.max_completion_tokens;
    const capped =
      Number.isFinite(requested) && requested > 0
        ? Math.min(requested, auth.max_tokens_cap)
        : auth.max_tokens_cap;
    if (payload.max_completion_tokens != null && payload.max_tokens == null) {
      payload.max_completion_tokens = capped;
    } else {
      payload.max_tokens = capped;
      if (payload.max_completion_tokens != null) payload.max_completion_tokens = capped;
    }
  }

  // Snapshot the NEUTRAL payload (resolved model, no provider/transform) BEFORE
  // shaping the OpenRouter body — the direct path's eligibility gate +
  // projectAllowedFields must run on this untransformed form (transformPayload
  // injects OpenRouter-only fields a direct provider 422s on).
  const basePayload = structuredClone(payload);

  // Shape the OpenRouter body IN PLACE on `payload`: provider_directive +
  // transforms + hp's strips + the OpenAI safety identifier (#657).
  if (auth.provider_directive && typeof auth.provider_directive === 'object') {
    payload.provider = auth.provider_directive;
  }
  try {
    transformPayload(payload);
  } catch (e) {
    log(`transform failed: ${e.message}`);
    reportEnclaveError(ERROR_CODES.TRANSFORM_FAILED, {
      request_id: requestId,
      credit_id: billedCreditId,
      model: reportableModel,
      query_source: querySource,
    });
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }
  // Before the free strip — hp injects the auto-router plugin inside
  // transformPayload, ahead of its own strip, and the strip deletes `plugins`.
  applyAutoRouterConfig(payload, auth.auto_router);
  if (auth.is_free) applyFreeModelStrip(payload);
  if (auth.strip_tools) applyToolStrip(payload);
  applySafetyIdentifier(payload, billedCreditId, cfg.safetySecret);

  // The OpenRouter request spec — the terminal fallback (fully-transformed body).
  const orBodyStr = JSON.stringify(payload);
  const orSpec = {
    isDirect: false,
    provider: 'openrouter',
    // The model id actually placed on the OpenRouter wire. Left unset until
    // now, so every OpenRouter receipt reported `upstream_model: null` — the
    // one route where the field is arguably most useful, because hp rewrites
    // `payload.model` on this path (auto-router selection, aliases, variant
    // suffixes) and the rewrite is invisible to the client otherwise.
    //
    // Read from the fully-transformed payload rather than the client's request:
    // the receipt's job is to state what was SENT, and the gap between the two
    // is precisely what it exists to expose.
    upstreamModel: typeof payload?.model === 'string' ? payload.model : null,
    bodyStr: orBodyStr,
    opts: {
      host: '127.0.0.1',
      port: cfg.orPort,
      servername: cfg.orHost,
      method: 'POST',
      path: '/api/v1/chat/completions',
      headers: {
        host: cfg.orHost,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(orBodyStr),
        authorization: `Bearer ${UPSTREAM_KEYS.openrouter}`,
        'http-referer': 'https://ppq.ai/',
        'x-title': 'PPQ.AI',
      },
    },
  };

  // Ordered upstream candidates from hp (Phase 1). An older hp sends none → OR;
  // a list missing the terminal OpenRouter candidate (contract violation)
  // gains one rather than risking a 502 once every direct candidate skips.
  const candidates = normalizeCandidates(auth.upstreams);

  // Try each in order. A DIRECT candidate must be eligible AND return 2xx, else
  // we drain it and fall to the next. OpenRouter is TERMINAL — piped regardless
  // of status (nothing follows it); only a connect error 502s.
  let chosen = null;
  // Remembered so the failure report can name the upstream that died last.
  let lastFailure = null;
  // Collected for the routing receipt (#58): why the enclave passed over the
  // candidates ahead of the one it used. Without these, "it went to OpenRouter"
  // is unexplained and reads as arbitrary.
  const skippedCandidates = [];
  const failedCandidates = [];
  for (let i = 0; i < candidates.length; i++) {
    const cand = candidates[i];
    const terminal = i === candidates.length - 1;
    let spec;
    if (isOpenRouter(cand)) {
      spec = orSpec;
    } else {
      // Dispatch on the candidate's wire dialect. 'bedrock' = the OpenAI
      // Responses API on bedrock-mantle (SigV4, plain-SSE response);
      // 'anthropic' = the Messages API on api.anthropic.com (x-api-key,
      // Anthropic SSE); everything else is the OpenAI chat dialect.
      const built =
        cand.api_style === 'bedrock'
          ? buildBedrockRequest({
              candidate: cand,
              basePayload,
              ports: UPSTREAM_PORTS,
              creds: bedrockCreds.get(),
            })
          : cand.api_style === 'anthropic'
            ? buildAnthropicRequest({
                candidate: cand,
                basePayload,
                ports: UPSTREAM_PORTS,
                keys: UPSTREAM_KEYS,
              })
            : buildDirectRequest({
                candidate: cand,
                basePayload,
                ports: UPSTREAM_PORTS,
                // key_ref 'vertex' resolves to a MINTED OAuth token, not a
                // static key. A null token (no SA key, tunnel down, endpoint
                // error) simply leaves 'vertex' absent from the map and the
                // builder skips with no_tunnel_or_key — OpenRouter serves.
                keys:
                  cand.key_ref === 'vertex'
                    ? { ...UPSTREAM_KEYS, vertex: (await vertexMinter.getToken()) || undefined }
                    : UPSTREAM_KEYS,
              });
      if (built.skip) {
        log(`direct ${cand.provider} skipped: ${built.skip}${built.offendingField ? ' ' + built.offendingField : ''}`);
        skippedCandidates.push({
          provider: cand.provider,
          reason: built.skip,
          field: built.offendingField,
        });
        continue;
      }
      spec = { ...built, isDirect: true };

      // #58 phase 3: refuse a family/host pairing the published map does not
      // permit. hp chooses the upstream and carries no measurement, so without
      // this an `anthropic/*` request could be served from api.fireworks.ai --
      // an expensive model on a cheap provider, invisible to attestation.
      //
      // SKIPPED, not fatal: OpenRouter is permitted for every family and is
      // terminal in every candidate list, so the answer still gets served.
      // Denying a substitution must not become a way to deny the user a reply.
      const bind = checkBinding(model, spec.opts?.servername);
      if (!bind.allowed) {
        log(
          `direct ${cand.provider} REFUSED: ${BINDING_VIOLATION} ` +
            `${model} -> ${spec.opts?.servername} (permitted: ${bind.permitted.join(',')})`,
        );
        skippedCandidates.push({
          provider: cand.provider,
          reason: BINDING_VIOLATION,
          field: spec.opts?.servername,
        });
        // Reported because a silent refusal is indistinguishable from a
        // provider outage, and this one means hp asked for something it should
        // not have.
        reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
          request_id: requestId,
          credit_id: billedCreditId,
          model,
          provider: cand.provider,
          upstream_status: 0,
          query_source: querySource,
        });
        continue;
      }
    }
    const attempt = await attemptUpstream(spec.opts, spec.bodyStr);
    if (attempt.res && (attempt.ok || terminal)) {
      chosen = { spec, res: attempt.res, statusCode: attempt.statusCode || 200 };
      break;
    }
    if (attempt.res) attempt.res.resume(); // discard the failed direct response body
    log(`upstream ${cand.provider} failed: ${attempt.statusCode || attempt.error?.message || 'unknown'}`);
    lastFailure = { provider: cand.provider, status: attempt.statusCode };
    failedCandidates.push({ provider: cand.provider, status: attempt.statusCode });
    if (terminal) {
      // Carries WHICH upstream died and with what status — the thing the client
      // cannot see (it only ever gets `enclave returned HTTP 502`) and the
      // reason a provider outage was previously indistinguishable from a bug.
      reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
        credit_id: billedCreditId,
        model: reportableModel,
        provider: lastFailure.provider,
        upstream_status: lastFailure.status,
        query_source: querySource,
      });
      return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
    }
  }
  if (!chosen) {
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      credit_id: billedCreditId,
      model: reportableModel,
      provider: lastFailure?.provider,
      upstream_status: lastFailure?.status,
      query_source: querySource,
    });
    return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
  }

  // A terminal candidate is chosen even when it answered 4xx/5xx — we pass the
  // upstream's error through rather than inventing one. That path still settles,
  // so without this report a provider returning 400 to every request would be
  // completely invisible on our side (Codex review).
  if (chosen.statusCode >= 400) {
    reportEnclaveError(ERROR_CODES.UPSTREAM_ERROR_STATUS, {
      request_id: requestId,
      credit_id: billedCreditId,
      model: reportableModel,
      provider: chosen.spec.isDirect ? chosen.spec.provider : 'openrouter',
      upstream_status: chosen.statusCode,
      query_source: querySource,
    });
  }

  const chosenDirect = chosen.spec.isDirect;
  const extractor = new CostExtractor({ isFreeModel });
  // OpenRouter: rebrand. Direct: hide the wire model id behind the public slug.
  const rewriter = chosenDirect
    ? directResponseRewriter(chosen.spec.upstreamModel, chosen.spec.orSlug)
    : new Rebrander();

  // For EHBP requests, chunk-encrypt the response back to the browser. Writes
  // are serialised through a promise chain to preserve chunk order.
  let respEnc = null;
  if (ehbpCtx) {
    respEnc = await ehbpRecipient.responseEncryptor(ehbpCtx.exportedSecret, ehbpCtx.requestEnc);
  }
  let writeChain = Promise.resolve();
  const writeOut = (buf) => {
    if (!buf || buf.length === 0) return;
    if (respEnc) {
      writeChain = writeChain.then(async () => res.write(await respEnc.encrypt(buf)));
    } else {
      res.write(buf);
    }
  };

  const upRes = chosen.res;
  // Translated dialects (Bedrock's Responses SSE, Anthropic's Messages SSE)
  // become chat-completions SSE BEFORE the extractor/rewriter, so both see
  // the same dialect they see from every other upstream.
  const translator =
    chosen.spec.apiStyle === 'bedrock'
      ? new ResponsesToChatSse({ upstreamModel: chosen.spec.upstreamModel })
      : chosen.spec.apiStyle === 'anthropic'
        ? new MessagesToChatSse({ upstreamModel: chosen.spec.upstreamModel })
        : null;
  const respHeaders = {
    'content-type': translator
      ? 'text/event-stream'
      : upRes.headers['content-type'] || 'application/json',
    'transfer-encoding': 'chunked',
  };
  if (respEnc) respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
  res.writeHead(chosen.statusCode, respHeaders);

  // The enclave's own statement of where this went, emitted BEFORE any upstream
  // bytes and through writeOut so it is sealed for EHBP clients. Only on event
  // streams: prepending a comment line to an application/json body would
  // corrupt a response that was otherwise fine (see receipt.mjs).
  const receipt = signedReceiptBytes(
    respHeaders['content-type'],
    buildReceipt({
      requestedModel: model,
      spec: chosen.spec,
      statusCode: chosen.statusCode,
      skipped: skippedCandidates,
      failed: failedCandidates,
    }),
    connectionSigningKey(req),
  );
  if (receipt) writeOut(receipt);

  upRes.on('data', (raw) => {
    const chunk = translator ? translator.feed(raw) : raw;
    if (translator && chunk.length === 0) return;
    extractor.feed(chunk);
    writeOut(rewriter.feed(chunk));
  });
  // Settle exactly once, from whichever of 'end' / 'error' fires first. An
  // upstream stream error used to skip settlement entirely: the user had the
  // partial answer, and whatever usage the stream had already reported — or,
  // on OpenRouter, the generation id hp can price from — was never sent.
  let settled = false;
  const settleNow = () => {
    if (settled) return;
    settled = true;
    const usage = extractor.finish();
    // Content-free billing metadata. For a direct upstream: bill on the public
    // or_slug (so hp margins match) and report provider + wire/served model ids
    // so hp prices from the catalog rate table (no OR cost / generation id).
    reportSettlement({
      request_id: String(requestId),
      settle_id: settleId,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: chosenDirect ? chosen.spec.orSlug : usage.model || model,
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens,
      total_cost_usd: chosenDirect ? 0 : usage.totalCost,
      cost_source: chosenDirect ? 'catalog-tokens' : 'stream',
      generation_id: chosenDirect ? '' : usage.generationId,
      query_source: querySource,
      cache_read_tokens: usage.cacheReadTokens,
      cache_write_tokens: usage.cacheWriteTokens,
      // Verbatim reasoning count; hp folds it into billed output ONLY for
      // providers whose descriptor marks reasoning additive (Vertex).
      reasoning_tokens: usage.reasoningTokens,
      // Must agree with horse-power's `hasWebSearch`, not just test plugins:
      // Auto mode declares the server tool instead, and Auto is the default for
      // a user who never touched the setting, so the old plugins-only test
      // recorded almost every enclave search as offline (#8).
      is_online: hasWebSearch(basePayload),
      is_free_model: isFreeModel,
      // Whether the CALLER asked for Auto — not the model the router landed on,
      // which travels as served_model. hp needs this to stamp autoModel; without
      // it, enclave-served Auto traffic is invisible in reporting (#790).
      //
      // Derived from the directive rather than re-parsing a model string: hp
      // already made this exact decision at /authorize (`is_auto_router`, on the
      // resolved BASE slug) and sends the allow-list iff it is true. Testing
      // basePayload.model here instead would report false for suffixed Auto
      // (`openrouter/auto:exacto`), since resolved_model carries the suffix.
      auto_model: Boolean(auth.auto_router),
      provider: chosenDirect ? chosen.spec.provider : 'openrouter',
      upstream_model: chosenDirect ? chosen.spec.upstreamModel : undefined,
      served_model: usage.model,
    });
  };

  upRes.on('end', () => {
    if (translator) {
      const tail = translator.finish();
      if (tail.length > 0) {
        extractor.feed(tail);
        writeOut(rewriter.feed(tail));
      }
    }
    writeOut(rewriter.finish());
    writeChain.then(() => res.end()).catch(() => { if (!res.writableEnded) res.end(); });
    settleNow();
  });
  upRes.on('error', (e) => {
    log(`upstream stream error: ${e.message}`);
    // The user saw a truncated answer and may already have been billed for the
    // prefill, so this is not merely cosmetic.
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      credit_id: billedCreditId,
      model: reportableModel,
      provider: chosenDirect ? chosen.spec.provider : 'openrouter',
      query_source: querySource,
    });
    if (!res.writableEnded) res.end();
    settleNow();
  });
}

/**
 * GET /attestation?nonce=<hex> — return a fresh NSM attestation document that
 * (a) proves this is a genuine Nitro enclave running image PCR0=…, (b) echoes
 * the client's nonce for freshness, and commits to BOTH key materials:
 *   public_key = the enclave's HPKE public key (browsers HPKE-seal to it)
 *   user_data  = SHA-256 of the TLS cert SPKI (programmatic TLS-in-enclave pin)
 * The document is AWS-signed, so it can be fetched over the untrusted channel.
 */
/**
 * SPKI of the certificate THIS connection was actually served.
 *
 * A single process-wide value is wrong the moment more than one certificate
 * exists, which ACME makes true: the shadow hostname gets an issued certificate
 * while everything else keeps the boot-time self-signed one. Binding the
 * attestation to a global meant committing to a certificate the client was NOT
 * served, so a client doing attested-TLS verification would reject a perfectly
 * good connection.
 *
 * Confirmed on the dev enclave 2026-09-03: after the first successful ACME
 * order the attested hash was 0b87e157... while clients were served c4fa8b65...
 * The feature broke the very property it exists to provide.
 *
 * `socket.getCertificate()` returns the LOCAL certificate for this connection,
 * which is exactly the one the peer saw. Falls back to the boot-time value when
 * unavailable, which is the single-certificate case and therefore correct.
 */
/**
 * The key whose certificate THIS connection was served, for signing the
 * routing receipt.
 *
 * MUST TRACK `connectionSpki`. The attestation commits to the SPKI of the
 * certificate the peer actually saw; a receipt signed with any other key cannot
 * be verified against that commitment, and `client/verify-receipt.mjs` reports
 * it as "this receipt did not come from that enclave" -- the exact alarm a real
 * attack would raise (#112).
 *
 * Not hypothetical: receipts were signed with the boot self-signed key
 * unconditionally, which agreed with the attestation only while nginx
 * terminated TLS and the enclave's own certificate was the boot one. The moment
 * an ACME certificate is served -- the whole point of #52 phase 3 -- they
 * diverged. The boot key remains correct precisely when no ACME certificate is
 * installed for this name.
 */
function connectionSigningKey(req) {
  return issuedSigningKey(req?.socket?.servername) || TLS_PRIVATE_KEY;
}

function connectionSpki(req) {
  try {
    const cert = req.socket?.getCertificate?.();
    // Derive the SPKI from the certificate DER, NOT from `cert.pubkey`.
    //
    // `pubkey` is not a consistent encoding: for RSA it is the SPKI DER, but
    // for EC it is the RAW uncompressed point (65 bytes for P-256). Hashing it
    // therefore produces a value that matches the boot-time computation for an
    // RSA certificate and silently does not for an EC one.
    //
    // That is exactly the shape here: boot.sh self-signs with RSA-2048 while
    // ACME issues a P-256 certificate, so the attested hash matched nothing
    // once an ACME certificate was in play. A local reproduction using RSA
    // passed and hid it; only a real ACME certificate on the dev enclave
    // exposed it (pubkeyLen=65).
    //
    // `cert.raw` is the full DER, so running it back through X509Certificate
    // reproduces the boot-time computation exactly, for either key type.
    if (cert && cert.raw) {
      const spkiDer = new X509Certificate(cert.raw).publicKey.export({
        type: 'spki',
        format: 'der',
      });
      return {
        hex: createHash('sha256').update(spkiDer).digest('hex'),
        b64: Buffer.from(spkiDer).toString('base64'),
      };
    }
  } catch (e) {
    log(`attestation: per-connection SPKI unavailable (${e.message}); using boot value`);
  }
  return { hex: CERT_SPKI_SHA256_HEX, b64: CERT_SPKI_DER_B64 };
}

async function handleAttestation(req, res) {
  const q = new URL(req.url, 'http://x').searchParams;
  const nonceHex = sanitizeNonceHex(q.get('nonce') || '');
  const spki = connectionSpki(req);
  const args = ['--public-key', HPKE_PUBLIC_KEY_HEX, '--user-data', spki.hex];
  if (nonceHex) args.push('--nonce', nonceHex);

  let docB64;
  try {
    const { stdout } = await execFileAsync('/app/attest', args, { timeout: 5000 });
    docB64 = stdout.trim();
  } catch (e) {
    log(`attest helper failed: ${e.message}`);
    return sendJson(res, 503, {
      error: { message: 'attestation unavailable', code: 503 },
    });
  }
  return sendJson(res, 200, {
    attestation_document_b64: docB64,
    hpke_public_key: HPKE_PUBLIC_KEY_HEX,
    cert_spki_sha256: spki.hex,
    // The SPKI the hash above is over, so a browser can verify a signed routing
    // receipt. Safe to serve: the client must hash it and match user_data in
    // the signed attestation before trusting it.
    cert_spki_der: spki.b64,
    format: 'nsm-cose-sign1',
  });
}

function requestRouter(req, res) {
  // CORS for browser clients.
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', '*');
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  // The browser's EHBP client must READ this response header to decrypt the
  // body; cross-origin JS cannot see it unless it is explicitly exposed, and
  // the failure is a `ProtocolError` on a request that otherwise succeeded.
  //
  // nginx supplies this today (nginx-enclave.conf, nginx-sni-split.conf), which
  // is exactly why it is set here BEFORE that proxy is retired (#52 phase 3):
  // moving the enclave onto :443 without this would break every browser client,
  // and no Node-based test would catch it — Node ignores CORS entirely, so the
  // interop suite passes either way. Setting it in both places is harmless
  // while both exist: identical values on a list-valued header.
  res.setHeader('access-control-expose-headers', 'Ehbp-Response-Nonce');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = (req.url || '').split('?')[0];
  if (req.method === 'GET' && url === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      keyLoaded: Boolean(OPENROUTER_API_KEY),
      bedrockCredsLoaded: Boolean(bedrockCreds.get()),
      key_sources: keySources(),
      acme_store: acmeStoreSelfTest,
      // What is actually being SERVED, not merely what sealing can do.
      acme_certificates: issuedCertificateSummary(),
      // Where the EHBP key came from this boot (#52 scaling). `store` is the
      // only steady-state answer; `generated` means browsers' sealed requests
      // stop decrypting at the next restart unless `hpke_identity_persisted`;
      // `rejected` means the store holds an identity this image could not
      // load and is being deliberately left alone -- needs a human.
      hpke_identity: hpkeIdentitySource,
      hpke_identity_persisted: hpkeIdentityPersisted,
      // Public, and the fleet property in one field: every worker on every box
      // must report the same value.
      hpke_public_key: HPKE_PUBLIC_KEY_HEX,
      workers: WORKER_COUNT,
      worker: cluster.isWorker ? cluster.worker.id : 0,
      pid: process.pid,
      // Who renews the certificate, and how (#52 DNS-01).
      acme_renewal: { mode: ACME_RENEWAL_MODE, authority: ACME_RENEWAL_AUTHORITY, ci_endpoint: Boolean(ACME_CI_TOKEN) },
    });
  }
  if (req.method === 'GET' && url === '/attestation') {
    return handleAttestation(req, res).catch((e) => {
      log(`attestation error: ${e.message}`);
      if (!res.headersSent)
        sendJson(res, 500, { error: { message: 'attestation failed', code: 500 } });
    });
  }
  if (req.method === 'POST' && (url === '/acme/csr' || url === '/acme/install')) {
    return handleAcmeCi(req, res, url).catch((e) => {
      log(`acme-ci error: ${e.message}`);
      if (!res.headersSent) sendJson(res, 500, { error: { message: 'internal', code: 500 } });
    });
  }
  if (
    req.method === 'POST' &&
    (url === '/v1/chat/completions' || url === '/chat/completions')
  ) {
    return handleChatCompletion(req, res).catch((e) => {
      log(`handler error: ${e.message}`);
      // Code only, never e.message — an unanticipated throw is exactly where an
      // error string is most likely to have content in it. Without this, any
      // failure outside the classified paths stays inside the enclave forever.
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, {});
      if (!res.headersSent)
        sendJson(res, 500, { error: { message: 'internal', code: 500 } });
    });
  }
  return sendJson(res, 404, { error: { message: 'not found', code: 404 } });
}

async function start() {
  if (!OPENROUTER_API_KEY) {
    log('WARNING: OPENROUTER_API_KEY not set — chat calls will 401 upstream');
  }
  const certPem = readFileSync(cfg.tlsCertPath);
  // Fingerprint the cert's public key (SPKI) so the attestation can commit to it
  // (user_data) for programmatic TLS-in-enclave clients.
  const spkiDer = new X509Certificate(certPem).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  CERT_SPKI_SHA256_HEX = createHash('sha256').update(spkiDer).digest('hex');
  CERT_SPKI_DER_B64 = Buffer.from(spkiDer).toString('base64');
  TLS_PRIVATE_KEY = createPrivateKey(readFileSync(cfg.tlsKeyPath));
  log(`TLS cert SPKI SHA-256: ${CERT_SPKI_SHA256_HEX}`);

  // The EHBP HPKE identity is resolved further down, AFTER the sealed store
  // has been read: it lives in that store now (#52 scaling), so order matters.

  // Sealed ACME store (#83): prove the attestation-gated round-trip at boot,
  // BEFORE anything depends on it. `genkey` has never run in this system and is
  // only exercisable in production, so this is where a wrong CMK allow-list
  // becomes visible — the failure mode that went unnoticed for months in #11.
  // Awaited rather than fired off: it is two KMS calls, and /health must not be
  // able to answer before the field it reports has been decided.
  const storeCreds = storeCredsFromEnv();
  const storeKms = storeCreds ? kmstoolBackend(storeCreds) : null;
  acmeStoreSelfTest = await selfTest({ kms: storeKms, log });
  if (!storeKms) log('acme-store: not configured (no CMK id); store is inert');

  // Bedrock creds channel: boot.sh forwards vsock:7001 to this loopback
  // listener, and passes any bedrock fields from the one-shot init blob via
  // BEDROCK_INIT_JSON so the first boot works before the host's first
  // refresh tick. Both are optional — without them the bedrock candidate is
  // simply skipped (no_tunnel_or_key).
  //
  // In cluster mode the primary does not serve, so it does not apply the blob
  // itself: it keeps the latest one for workers spawned later and fans each
  // push out to the workers that exist now.
  const fleet = createFleet({ workers: WORKER_COUNT, log });
  fleetRef = fleet;
  if (fleet.size > 1) bedrockCreds.onBlob = (blob) => fleet.bedrockBlob(blob);
  const credsPort = Number(process.env.CREDS_PORT || 0);
  if (credsPort > 0) {
    bedrockCreds.listen(credsPort);
    log(`bedrock creds listener on 127.0.0.1:${credsPort}`);
  }
  if (process.env.BEDROCK_INIT_JSON) {
    try {
      const blob = JSON.parse(process.env.BEDROCK_INIT_JSON);
      if (fleet.size > 1) fleet.bedrockBlob(blob);
      else await bedrockCreds.applyBlob(blob);
    } catch (e) {
      log(`bedrock init creds blob rejected: ${e.message}`);
    }
    delete process.env.BEDROCK_INIT_JSON;
  }

  const defaultTlsKey = readFileSync(cfg.tlsKeyPath);

  // Set inside the ACME block, read by the identity step after it: the store
  // is opened exactly once per boot, and both the certificate and the EHBP
  // identity come out of that one opening.
  let cached = null;
  // When no order will run this boot, this is how a freshly generated identity
  // still reaches the store. Null whenever an order is pending, because the
  // order's own seal carries the identity and two writers would race.
  let persistIdentity = null;
  // The order to place once something is listening -- this process, or every
  // worker. Null when the cached certificate is current.
  let placeOrder = null;

  // In-enclave certificate issuance (#52), opt-in and never fatal.
  //
  // TWO DIFFERENT MOMENTS, and the order is load-bearing:
  //
  //   the cached certificate is installed BEFORE listen, so a restart serves
  //   the real certificate on its very first handshake instead of briefly
  //   presenting the self-signed one;
  //
  //   an ORDER, when one is needed, fires after listen and asynchronously,
  //   because the TLS-ALPN-01 challenge is a handshake to this very server --
  //   ordering before it can accept connections would deadlock.
  //
  // A failure leaves the shadow hostname on whatever it already had: the cached
  // certificate if there was one, otherwise the self-signed certificate, which
  // is exactly the state before this existed.
  //
  // ACME_DIRECTORY defaults to staging. Production allows 5 duplicate
  // certificates per week with no undo, so it stays opt-in until the sealed
  // store below has been observed carrying a certificate across a restart.
  if (process.env.ACME_DOMAIN) {
    // Comma-separated for a SAN certificate covering several names. One order
    // instead of one per name: Let's Encrypt's duplicate-certificate limit is
    // 5 per exact set of names per week, so one SAN order spends one of them
    // where per-name orders would spend one each.
    const domains = process.env.ACME_DOMAIN.split(',').map((d) => d.trim()).filter(Boolean);
    const domain = domains[0];
    const tunnels = {
      'acme-staging-v02.api.letsencrypt.org': Number(process.env.ACME_STAGING_PORT || 0),
      'acme-v02.api.letsencrypt.org': Number(process.env.ACME_PROD_PORT || 0),
    };
    const directoryUrl =
      process.env.ACME_DIRECTORY || 'https://acme-staging-v02.api.letsencrypt.org/directory';
    const storePort = Number(process.env.STORE_PORT || 0);

    // The cached certificate is installed BEFORE listen, so a restart serves
    // the real certificate from the first handshake rather than briefly
    // presenting the self-signed one while an order runs.
    cached = await loadCachedCertificate({
      raw: process.env.ACME_STORE_BLOB,
      kms: storeKms,
      domains,
      directoryUrl,
      log,
    });
    // Read once: boot.sh cannot unset it for us, and it has served its purpose.
    delete process.env.ACME_STORE_BLOB;
    if (cached.payload) {
      // Install under EVERY name the certificate covers: SNICallback looks up by
      // the name the client asked for, so a SAN cert filed under only the first
      // one would leave the others on the boot self-signed certificate.
      for (const name of cached.payload.domains?.length ? cached.payload.domains : [domain]) {
        setIssuedCertificate(name, { key: cached.payload.key, cert: cached.payload.cert });
      }
      log(`acme: serving ${domains.join(', ')} from the sealed store (expires ${cached.payload.notAfter})`);
    }

    // Order only when there is nothing servable or it is inside the renewal
    // window. This is the whole point of #83: without it every restart spends
    // one of five weekly duplicates.
    // Only the renewal authority ever orders, and in dns01-ci mode not even
    // it does: CI runs the order and brings the certificate to /acme/install.
    if (cached.renew && !ACME_RENEWAL_AUTHORITY) {
      log('acme: certificate wants renewal but this box is not the renewal authority; no order (the next sealed store arrives from S3)');
    } else if (cached.renew && ACME_RENEWAL_MODE === 'dns01-ci') {
      log('acme: certificate wants renewal; delegated to CI (dns01-ci), no in-enclave order');
    } else if (cached.renew) {
      placeOrder = () =>
        obtainCertificate({
          domains,
          directoryUrl,
          contactEmail: process.env.ACME_EMAIL || undefined,
          fetchImpl: createAcmeFetch(tunnels),
          log,
          // Cluster mode: every worker must hold the challenge certificate
          // before the CA is told to validate (see clusterProto.mjs). In
          // single-process mode these are no-ops.
          onChallengeArmed: (name, creds) => fleet.armChallenge(name, creds),
          onChallengeCleared: (name) => fleet.clearChallenge(name),
        })
          .then(({ key, cert, domains: issuedFor }) =>
            persistIssued({ key, cert, domains: issuedFor?.length ? issuedFor : [domain], source: 'in-enclave order' }),
          )
          .catch((e) => {
            // A failed renewal must not disturb a cached certificate that is
            // still valid -- it stays installed and we retry next boot.
            log(`acme: order for ${domain} failed: ${e.message}`);
            if (cached.servable) log('acme: continuing on the cached certificate');
          });
    } else {
      log(`acme: ${domain} certificate is current; no order placed`);
    }
    // When no order will run this boot (current certificate or delegated
    // renewal) nothing else writes the store, so a freshly generated identity
    // gets in by re-sealing the servable payload here. ONLY THE AUTHORITY
    // WRITES THE STORE: a fleet box re-sealing an older payload would publish
    // it to S3 over the authority's newer one (single-writer, #52 step 3).
    if (!placeOrder && cached.payload && storeKms && ACME_RENEWAL_AUTHORITY) {
      persistIdentity = async (hpke) => {
        const blob = await sealStore({ ...cached.payload, hpke }, { kms: storeKms, domain });
        return saveSealedBlob(blob, { port: storePort, log });
      };
    }
    acmeCtx = { storeKms, storePort, domain, domains, directoryUrl, cached };
  }

  // EHBP HPKE identity (#52 scaling). From the sealed store when it holds one,
  // so a restart — and later every box in a fleet unsealing the same blob —
  // presents the SAME public key. Fresh only when the store has none, and then
  // persisted so that it is fresh exactly once.
  const identity = await resolveHpkeIdentity({ stored: cached?.unsealed?.hpke ?? null, log });
  ehbpRecipient = identity.recipient;
  hpkeIdentitySource = identity.source;
  HPKE_PUBLIC_KEY_HEX = await ehbpRecipient.publicKeyHex();
  log(`EHBP HPKE public key: ${HPKE_PUBLIC_KEY_HEX} (${hpkeIdentitySource})`);
  if (identity.source === 'store') {
    hpkeIdentityPersisted = true;
  } else if (identity.source === 'rejected') {
    // Serve, do not write. See hpkeIdentity.mjs for why overwriting here would
    // be a silent fleet-wide key rotation that also destroys the evidence.
    hpkeIdentityPersisted = false;
  } else if (persistIdentity) {
    try {
      hpkeIdentityPersisted = Boolean(await persistIdentity(await ehbpRecipient.toJSON()));
      log(`hpke-identity: ${hpkeIdentityPersisted ? 'persisted to' : 'NOT persisted to'} the sealed store`);
    } catch (e) {
      hpkeIdentityPersisted = false;
      log(`hpke-identity: persist failed (${e.message}); this key lives until the next restart`);
    }
  } else if (placeOrder && storeKms) {
    // The pending order seals the store when it completes and carries the
    // identity with it; hpkeIdentityPersisted is set there.
    log('hpke-identity: will be persisted with the certificate order');
  } else if (!ACME_RENEWAL_AUTHORITY) {
    hpkeIdentityPersisted = false;
    log('hpke-identity: not the renewal authority; not writing the store (the authority publishes it)');
  } else {
    hpkeIdentityPersisted = false;
    log('hpke-identity: no sealed store; this key lives until the next restart');
  }

  // Serve. One process binds directly; a cluster forks workers that bind the
  // same port through the primary, and the pending order (if any) is placed
  // only once every worker can answer the challenge handshake.
  if (fleet.size <= 1) {
    const server = https.createServer(tlsOptions(defaultTlsKey, certPem), requestRouter);
    if (placeOrder) server.on('listening', placeOrder);
    server.listen(cfg.inboundPort, '127.0.0.1', () =>
      log(`enclave proxy listening (TLS) on 127.0.0.1:${cfg.inboundPort}`),
    );
  } else {
    fleet.start({ onAllListening: placeOrder });
  }
}

/**
 * Install a certificate under every name it covers, tell the workers, then
 * seal and save it with the EHBP identity. Shared by the in-enclave order and
 * the CI-driven renewal; only the PRIMARY (or the single process) calls it.
 */
async function persistIssued({ key, cert, domains: names, source }) {
  for (const name of names) setIssuedCertificate(name, { key, cert });
  // Workers get the certificate NOW. Sealing and saving come after and can
  // fail; a persistence failure must not leave workers on the previous
  // certificate while the primary holds the new one.
  fleetRef.issued(names, { key, cert });
  log(`acme: ${names.join(', ')} now served with an ACME certificate (${source})`);
  const ctx = acmeCtx || {};
  if (!ctx.storeKms) {
    log('acme-store: no CMK configured; certificate NOT persisted');
    return { persisted: false, notAfter: leafValidity(cert).notAfter };
  }
  if (!ACME_RENEWAL_AUTHORITY) {
    // Cannot happen today (a non-authority never orders or installs), kept
    // as the guard it is: the store has exactly one writer.
    log('acme-store: not the renewal authority; certificate NOT persisted');
    return { persisted: false, notAfter: leafValidity(cert).notAfter };
  }
  // Seal before announcing success. leafValidity throws on a chain we cannot
  // parse, which is better found here than on the boot that depends on
  // knowing when this expires.
  const { notAfter } = leafValidity(cert);
  const blob = await sealStore(
    {
      domain: ctx.domain,
      domains: names,
      directoryUrl: ctx.directoryUrl,
      cert,
      key,
      notAfter,
      // The EHBP identity rides with the certificate (#52 scaling): a renewal
      // must not drop the key browsers seal to. A REJECTED stored identity is
      // carried forward verbatim rather than replaced: the store authenticated
      // it, so what it holds is evidence of a fault, not material to rotate.
      hpke: hpkeIdentitySource === 'rejected' ? ctx.cached?.unsealed?.hpke : await ehbpRecipient.toJSON(),
    },
    { kms: ctx.storeKms, domain: ctx.domain },
  );
  const saved = await saveSealedBlob(blob, { port: ctx.storePort, log });
  log(`acme-store: certificate ${saved ? 'persisted' : 'NOT persisted'} (expires ${notAfter})`);
  if (hpkeIdentitySource === 'generated') hpkeIdentityPersisted = Boolean(saved);
  fleetRef.health({ hpkeIdentityPersisted });
  return { persisted: Boolean(saved), notAfter };
}

// The fleet handle start() creates; persistIssued and the RPC need it after
// start() has returned. A no-op fleet until then (and in every worker).
let fleetRef = { issued: () => {}, health: () => {} };

/** Constant-time bearer check for the CI renewal routes. */
function ciTokenOk(req) {
  if (!ACME_CI_TOKEN) return false;
  const h = String(req.headers.authorization || '');
  if (!h.startsWith('Bearer ')) return false;
  const a = createHash('sha256').update(h.slice(7)).digest();
  const b = createHash('sha256').update(ACME_CI_TOKEN).digest();
  return timingSafeEqual(a, b);
}

/**
 * POST /acme/csr     -> { csr_der_b64, domains }   a CSR over a fresh in-enclave key
 * POST /acme/install -> { notAfter, persisted }    install the certificate CI obtained
 *
 * Indistinguishable from an unknown route unless this box is the renewal
 * authority in dns01-ci mode AND the bearer token matches. The work itself
 * is single-writer and runs in the primary (RPC from a worker).
 */
async function handleAcmeCi(req, res, url) {
  if (ACME_RENEWAL_MODE !== 'dns01-ci' || !ACME_RENEWAL_AUTHORITY || !ciTokenOk(req)) {
    return sendJson(res, 404, { error: { message: 'not found', code: 404 } });
  }
  try {
    if (url === '/acme/csr') {
      return sendJson(res, 200, await callPrimary('acme-csr', {}));
    }
    const raw = await readRawBody(req, 64 * 1024);
    let body;
    try {
      body = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: { message: 'body must be JSON {cert}', code: 400 } });
    }
    // Install seals through KMS and saves through the parent; give it time.
    return sendJson(res, 200, await callPrimary('acme-install', { cert: body?.cert }, 120_000));
  } catch (e) {
    // Our own validation messages (key mismatch, name not covered, no
    // pending CSR) -- safe to return, and the CI job needs them.
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }
}

/** The single-writer half of the CI renewal; runs in the primary. */
async function primaryRpc(kind, payload) {
  switch (kind) {
    case 'acme-csr': {
      if (!acmeCtx?.domains?.length) throw new Error('ACME is not configured on this box');
      const r = beginRenewalCsr({ domains: acmeCtx.domains });
      log(`acme: CSR handed to CI for ${r.domains.join(', ')}`);
      return r;
    }
    case 'acme-install': {
      // Trust roots come from the image (trustRoots.mjs); the env override
      // exists for tests only -- boot.sh never exports it, so no init blob
      // can relax it.
      const issued = completeRenewal({ cert: payload?.cert, trustRootsPem: process.env.ACME_TRUST_ROOTS_PEM || undefined });
      if (issued.repeated) {
        log('acme: install repeated for an already-installed certificate; answering idempotently');
        return { notAfter: issued.notAfter, persisted: true, domains: issued.domains, fingerprint256: issued.fingerprint256, repeated: true };
      }
      const r = await persistIssued({ ...issued, source: 'CI DNS-01' });
      return { notAfter: issued.notAfter, persisted: r.persisted, domains: issued.domains, fingerprint256: issued.fingerprint256 };
    }
    default:
      throw new Error(`unknown rpc ${kind}`);
  }
}

// Worker side of the RPC: ask the primary, wait for its reply.
const rpcPending = new Map();
let rpcSeq = 0;
function callPrimary(kind, payload, timeoutMs = 30_000) {
  if (cluster.isPrimary) return primaryRpc(kind, payload);
  const id = ++rpcSeq;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      rpcPending.delete(id);
      reject(new Error(`primary did not answer ${kind} within ${timeoutMs}ms`));
    }, timeoutMs);
    rpcPending.set(id, { resolve, reject, t });
    process.send({ type: MSG.RPC, id, kind, payload });
  });
}

/** TLS server options; identical for the single process and for every worker. */
function tlsOptions(defaultTlsKey, certPem) {
  return {
    key: defaultTlsKey,
    cert: certPem,
    minVersion: 'TLSv1.2',
    // TLS-ALPN-01 (#52). Both hooks are needed and neither is useful alone:
    // negotiating acme-tls/1 without presenting the challenge certificate fails
    // the order with no useful diagnostic, and presenting that certificate to an
    // ordinary client breaks it. Each is scoped to a name with a live challenge,
    // so with none pending the server behaves exactly as it did before.
    ALPNCallback: selectAlpn,
    SNICallback: (servername, cb) => {
      if (hasPendingChallenge(servername)) {
        const creds = challengeCredentials(servername);
        try {
          return cb(null, createSecureContext({ key: creds.key, cert: creds.cert }));
        } catch (e) {
          log(`acme: challenge context failed for ${servername}: ${e.message}`);
        }
      }
      // An ACME-issued certificate for this name, once an order has completed.
      const issued = issuedCredentials(servername);
      if (issued) {
        try {
          return cb(null, createSecureContext({ key: issued.key, cert: issued.cert }));
        } catch (e) {
          log(`acme: issued context failed for ${servername}: ${e.message}`);
        }
      }
      // null context = fall back to the server's default, i.e. today's cert.
      return cb(null, null);
    },
  };
}

/**
 * The primary's view of its workers (#52 scaling, step 5). With `workers <= 1`
 * every method is a no-op and `start` is never called, so single-process boots
 * are untouched. See clusterProto.mjs for the message contract.
 */
function createFleet({ workers, log }) {
  if (workers <= 1) {
    return {
      size: 1,
      armChallenge: async () => {},
      clearChallenge: async () => {},
      issued: () => {},
      health: () => {},
      bedrockBlob: () => {},
      start: () => {},
    };
  }

  let lastBedrockBlob = null;
  let seq = 0;
  let orderPlaced = false;
  let onAllListening = null;
  let fastFailures = 0;
  const acks = new Map();
  // Readiness is the SET of workers currently listening, not a counter: a
  // worker that listened and then died must not keep counting.
  const listening = new Set();
  // Challenges armed by an in-flight order. Part of every worker's state, so
  // a worker respawned mid-order can answer the validating handshake.
  const challenges = new Map();

  const live = () => Object.values(cluster.workers || {}).filter(Boolean);
  const send = (w, msg) => {
    try {
      w.send(msg);
    } catch (e) {
      log(`cluster: send to worker ${w.id} failed: ${e.message}`);
    }
  };
  const broadcast = (msg) => {
    for (const w of live()) send(w, msg);
  };
  // Broadcast and wait for every live worker to say it applied the message.
  const broadcastAcked = (msg, timeoutMs = 10_000) => {
    const targets = live();
    if (targets.length === 0) return Promise.resolve();
    const id = ++seq;
    return new Promise((resolve, reject) => {
      const pending = new Set(targets.map((w) => w.id));
      const timer = setTimeout(() => {
        acks.delete(id);
        reject(new Error(`workers ${[...pending].join(',')} did not acknowledge ${msg.type}`));
      }, timeoutMs);
      acks.set(id, {
        pending,
        done: () => {
          clearTimeout(timer);
          acks.delete(id);
          resolve();
        },
      });
      for (const w of targets) send(w, { ...msg, ack: id });
    });
  };

  const stateMessage = async () => ({
    type: MSG.STATE,
    workers,
    hpke: await ehbpRecipient.toJSON(),
    hpkeIdentitySource,
    hpkeIdentityPersisted,
    acmeStoreSelfTest,
    issued: issuedCertificateEntries(),
    challenges: [...challenges.entries()],
    bedrockBlob: lastBedrockBlob,
  });

  const onMessage = (w, m) => {
    if (!isMessage(m)) return;
    if (m.type === MSG.RPC) {
      primaryRpc(m.kind, m.payload).then(
        (result) => send(w, { type: MSG.RPC_REPLY, id: m.id, result }),
        (e) => send(w, { type: MSG.RPC_REPLY, id: m.id, error: e.message }),
      );
      return;
    }
    if (m.type === MSG.ACK) {
      const a = acks.get(m.ack);
      if (!a) return;
      a.pending.delete(w.id);
      if (a.pending.size === 0) a.done();
    } else if (m.type === MSG.LISTENING) {
      listening.add(w.id);
      log(`cluster: worker ${w.id} listening (${listening.size}/${workers})`);
      if (listening.size >= workers && onAllListening && !orderPlaced) {
        orderPlaced = true;
        onAllListening();
      }
    }
  };

  const spawn = () => {
    const startedAt = Date.now();
    const w = cluster.fork();
    w.on('online', () => {
      stateMessage().then(
        (st) => send(w, st),
        (e) => log(`cluster: could not build state for worker ${w.id}: ${e.message}`),
      );
    });
    w.on('message', (m) => onMessage(w, m));
    w.on('exit', (code, signal) => {
      listening.delete(w.id);
      // Its acks can never arrive. Dropping it is correct, not optimistic: the
      // replacement receives every active challenge in its state and installs
      // them before it listens, so nothing the dead worker was asked to hold
      // is lost.
      for (const a of acks.values()) {
        a.pending.delete(w.id);
        if (a.pending.size === 0) a.done();
      }
      // A worker that dies within 10s of starting is a deterministic failure
      // (bad state, listen error), not a crash under load. Back off, and after
      // ten in a row take the enclave down visibly rather than spin forever.
      const fast = Date.now() - startedAt < 10_000;
      fastFailures = fast ? fastFailures + 1 : 0;
      if (fastFailures >= 10) {
        log(`cluster: worker ${w.id} exited (${signal || code}); ${fastFailures} fast failures in a row -- giving up`);
        process.exit(1);
      }
      const delay = fast ? Math.min(30_000, 1000 * 2 ** Math.min(fastFailures - 1, 5)) : 1000;
      log(`cluster: worker ${w.id} exited (${signal || code}); respawning in ${delay}ms`);
      setTimeout(spawn, delay);
    });
  };

  return {
    size: workers,
    armChallenge: (name, creds) => {
      challenges.set(name, { key: creds.key, cert: creds.cert });
      return broadcastAcked({ type: MSG.CHALLENGE, name, key: creds.key, cert: creds.cert });
    },
    // Acknowledged, but never allowed to fail the order: by the time a
    // challenge is cleared the order is already decided.
    clearChallenge: async (name) => {
      challenges.delete(name);
      try {
        await broadcastAcked({ type: MSG.CHALLENGE_CLEAR, name });
      } catch (e) {
        log(`cluster: challenge clear for ${name} not fully acknowledged (${e.message})`);
      }
    },
    issued: (names, { key, cert }) => broadcast({ type: MSG.ISSUED, names, key, cert }),
    health: (fields) => broadcast({ type: MSG.HEALTH, ...fields }),
    bedrockBlob: (blob) => {
      lastBedrockBlob = blob;
      broadcast({ type: MSG.BEDROCK, blob });
    },
    start: ({ onAllListening: cb } = {}) => {
      onAllListening = cb || null;
      log(`cluster: starting ${workers} workers`);
      for (let i = 0; i < workers; i += 1) spawn();
    },
  };
}

/**
 * A worker: everything single-writer already happened in the primary. Wait for
 * its state, install it, serve on the shared port, keep applying updates.
 */
async function workerMain() {
  // Attach BEFORE the first await: the primary sends state the moment the
  // worker is online, and a message with no listener is dropped.
  const stateP = new Promise((resolve) => {
    const onFirst = (m) => {
      if (isMessage(m) && m.type === MSG.STATE) {
        process.off('message', onFirst);
        resolve(m);
      }
    };
    process.on('message', onFirst);
  });

  const certPem = readFileSync(cfg.tlsCertPath);
  const spkiDer = new X509Certificate(certPem).publicKey.export({ type: 'spki', format: 'der' });
  CERT_SPKI_SHA256_HEX = createHash('sha256').update(spkiDer).digest('hex');
  CERT_SPKI_DER_B64 = Buffer.from(spkiDer).toString('base64');
  TLS_PRIVATE_KEY = createPrivateKey(readFileSync(cfg.tlsKeyPath));
  const defaultTlsKey = readFileSync(cfg.tlsKeyPath);

  const state = await stateP;
  // The primary already validated this identity; a failure here is a bug, and
  // a worker that cannot decrypt what the attestation advertises must not serve.
  ehbpRecipient = await EhbpRecipient.fromJSON(state.hpke);
  HPKE_PUBLIC_KEY_HEX = await ehbpRecipient.publicKeyHex();
  hpkeIdentitySource = state.hpkeIdentitySource;
  hpkeIdentityPersisted = state.hpkeIdentityPersisted;
  acmeStoreSelfTest = state.acmeStoreSelfTest;
  for (const [name, creds] of state.issued || []) setIssuedCertificate(name, creds);
  // Challenges from an order in flight: installed BEFORE listen, so a worker
  // respawned mid-order can answer the validating handshake.
  for (const [name, creds] of state.challenges || []) setPendingChallenge(name, creds);

  // Steady-state updates. Attached BEFORE the (possibly slow, KMS-bound) blob
  // apply below, so a refresh arriving during initialisation is not dropped.
  process.on('message', (m) => {
    if (!isMessage(m)) return;
    switch (m.type) {
      case MSG.CHALLENGE:
        setPendingChallenge(m.name, { key: m.key, cert: m.cert });
        if (m.ack) process.send({ type: MSG.ACK, ack: m.ack });
        break;
      case MSG.CHALLENGE_CLEAR:
        setPendingChallenge(m.name, null);
        if (m.ack) process.send({ type: MSG.ACK, ack: m.ack });
        break;
      case MSG.ISSUED:
        for (const name of m.names || []) setIssuedCertificate(name, { key: m.key, cert: m.cert });
        break;
      case MSG.HEALTH:
        if (typeof m.hpkeIdentityPersisted === 'boolean') hpkeIdentityPersisted = m.hpkeIdentityPersisted;
        break;
      case MSG.BEDROCK:
        void bedrockCreds.applyBlob(m.blob);
        break;
      case MSG.RPC_REPLY: {
        const p = rpcPending.get(m.id);
        if (!p) break;
        clearTimeout(p.t);
        rpcPending.delete(m.id);
        if (m.error) p.reject(new Error(m.error));
        else p.resolve(m.result);
        break;
      }
      default:
        break;
    }
  });
  if (state.bedrockBlob) await bedrockCreds.applyBlob(state.bedrockBlob);

  const server = https.createServer(tlsOptions(defaultTlsKey, certPem), requestRouter);
  server.listen(cfg.inboundPort, '127.0.0.1', () => {
    log(`cluster: worker ${cluster.worker.id} listening (TLS) on 127.0.0.1:${cfg.inboundPort}`);
    process.send({ type: MSG.LISTENING });
  });
}

const main = cluster.isPrimary ? start : workerMain;
main().catch((e) => {
  log(`fatal start error: ${e.message}`);
  process.exit(1);
});
