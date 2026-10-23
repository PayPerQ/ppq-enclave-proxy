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
import { createServedIdentity } from './servedIdentity.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  decideSmartRoute,
  isSmartRoutingModel,
  parseAutoclawDirective,
} from './smartRouting.mjs';
import {
  resolveModel,
  transformPayload,
  applySafetyIdentifier,
  applyFreeModelStrip,
  applySpendCap,
  applyAutoRouterConfig,
  parseAutoRouter,
  applyToolStrip,
  applyWebPluginDirective,
  parseProviderFloor,
  applyProviderFloor,
  applyHardProviderPin,
  applyProviderDirective,
  webSearchEngineOf,
} from './routing.mjs';
import { FIREWORKS_WIRE_PROVIDERS, refusesUnauthorizedFree } from './eligibility.mjs';
import { createSettleQueue, classifySettleStatus } from './settleQueue.mjs';
import {
  ERROR_CODES,
  buildErrorReport,
  classifyModelRejection,
  piiFailureReason,
  handlerFailureFields,
  RESPONSE_SEAL_FAILED,
} from './errorReport.mjs';
import { CostExtractor } from './cost.mjs';
import { Rebrander, directResponseRewriter } from './rebrand.mjs';
import {
  MAX_ERROR_BODY_BYTES,
  sanitizeUpstreamErrorBody,
  sanitizedErrorBodyBuffer,
  sanitizedErrorStream,
} from './upstreamErrorBody.mjs';
import { RECEIPT_HERE, ReceiptGate, buildReceipt, canCarryReceipt, servedModelReport, signedReceiptBytes, signedReceiptHeaders } from './receipt.mjs';
import { keySources } from './keySources.mjs';
import {
  SELF_TEST_REASONS, kmstoolBackend, leafValidity, loadCachedCertificate, saveSealedBlob, sealStore,
  selfTest, storeCredsFromEnv, storeKeyIdStatus,
} from './acmeStore.mjs';
import { hasWebSearch } from './webSearchTransforms.mjs';
import { loadTokenizer, measureInput } from './inputEstimate.mjs';
import { OutputCounter, OVERFLOW_CHARS_PER_TOKEN } from './outputCount.mjs';
import { ReasoningMirror } from './reasoningMirror.mjs';
import { VeniceCitationTranslator } from './veniceCitations.mjs';
import { classifyDirectOnlyRefusal, directOnlyNamespaceFor } from './directOnly.mjs';
import {
  DECISIONS_COST_SOURCE,
  DECISIONS_UPSTREAM_PATH,
  MAX_REQUEST_BODY_BYTES as DECISIONS_MAX_REQUEST_BODY_BYTES,
  MAX_RESPONSE_BYTES as DECISIONS_MAX_RESPONSE_BYTES,
  UPSTREAM_DEADLINE_MS as DECISIONS_UPSTREAM_DEADLINE_MS,
  decisionsUsage,
  measureDecisionsInput,
  validateDecisionsRequest,
} from './decisions.mjs';
import {
  COUNT_TOKENS_INTENT,
  COUNT_TOKENS_PATH,
  COUNT_TOKENS_UPSTREAM_PATH,
  MAX_REQUEST_BODY_BYTES as MESSAGES_MAX_REQUEST_BODY_BYTES,
  MESSAGES_DIALECT,
  MESSAGES_ENDPOINT,
  MESSAGES_PATH,
  anthropicFirstPartyId,
  projectCountTokensBody,
} from './messages.mjs';
import { RESPONSES_DIALECT, RESPONSES_PATHS } from './responses.mjs';
import { BINDING_VIOLATION, candidateLabel, checkBindings, checkProviderBinding } from './upstreamBinding.mjs';
import {
  challengeCredentials,
  hasPendingChallenge,
  issuedCredentials,
  issuedSigningKey,
  challengeSigningKey,
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
import {
  FOUNDRY_HOST,
  buildDirectRequest,
  computeSessionAffinity,
  createTunnelFetch,
  isOpenRouter,
  normalizeCandidates,
} from './upstreams.mjs';
import { DEFAULT_TIMEOUT_MS as PII_DEFAULT_TIMEOUT_MS } from './pii/detector.mjs';
import { createAttestedDetector, DETECTOR_PLACEMENTS } from './pii/attestedDetector.mjs';
import { PII_ERRORS, createResponseRestorer, piiErrorBody, piiErrorMessage, redactBody, takePiiFlag } from './pii/pipeline.mjs';

/** Most a chat answer's PII restorer holds; the Messages/Responses bound. */
const PII_RESTORE_MAX_BYTES = 4 * 1024 * 1024;
import * as piiChatDialect from './pii/dialects/chat.mjs';
import * as piiMessagesDialect from './pii/dialects/messages.mjs';
import * as piiResponsesDialect from './pii/dialects/responses.mjs';
import { buildBedrockRequest, ResponsesToChatSse } from './bedrock.mjs';
import { buildAnthropicRequest, MessagesToChatSse } from './anthropic.mjs';
import { BedrockCredsHolder } from './bedrockCreds.mjs';
import { VertexTokenMinter } from './vertexAuth.mjs';
import { resolveHpkeIdentity } from './hpkeIdentity.mjs';
import { EhbpRecipient } from './ehbp-server.mjs';
import { MSG, isMessage, workerCount } from './clusterProto.mjs';
import { createPassthrough, routeDecision } from './passthrough.mjs';
import { authorizeHeaders } from './authorizeHeaders.mjs';
import {
  createBalanceBackoff,
  isBalanceBackoffRefusal,
  presentedCredentialKey,
  retryAfterSeconds,
} from './balanceBackoff.mjs';
import {
  ENCAP_KEY_HEADER,
  KEY_CONFIG_MISMATCH_STATUS,
  RESPONSE_NONCE_HEADER,
  sealedAnswerNonce,
  TINFOIL_COST_SOURCE,
  TINFOIL_HOST,
  TINFOIL_PROVIDER,
  USAGE_METRICS_HEADER,
  abortedRelayOutputFloor,
  buildTinfoilRequest,
  claimedPrivateModel,
  createBundleCache,
  createResponseOpener,
  createTinfoilAttestor,
  decryptedStream,
  hasTinfoilCandidate,
  isPrivateModel,
  isTinfoilCandidate,
  parseUsageMetrics,
  privateCandidates,
  querySourceOf,
  refusesMisroutedToTinfoil,
  refusesUnroutedPrivate,
  relayHeaders,
  relayResponseHeaders,
  routerModelId,
  toolIdOf,
  usageMetricsOf,
} from './tinfoil.mjs';
import { listenWithProxyProtocol } from './proxyListener.mjs';
import { createTraceRecorder, describeRequestShape, resolveRequestId, routeBailField } from './trace.mjs';
import { FirstTokenDetector, detectFirstTokenKind } from './firstToken.mjs';
import { createCounters } from './counters.mjs';
import { pinHpHost } from './hpHosts.mjs';

const execFileAsync = promisify(execFile);

// Per-worker request counters, surfaced on /health (counters.mjs). Enum keys
// and integers only.
const counters = createCounters();

// Identity stamped on every request trace (trace.mjs): the image version, and
// the EC2 instance id when the parent supplied one (send-init.sh reads it from
// IMDSv2 into the init blob; boot.sh exports it). Lets support tell "one box
// is slow" from "the fleet is slow" without anything about the request.
const ENCLAVE_VERSION = (() => {
  try {
    return String(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
  } catch {
    return '0.0.0';
  }
})();
const ENCLAVE_BOX_ID = process.env.ENCLAVE_BOX_ID || '';

// Bounded like settlePostOnce: without this a hung horse-power held the client
// open indefinitely, and the outage left no report because a request that
// never finishes authorizing never reaches a reporting path.
const AUTHORIZE_TIMEOUT_MS = 15_000;

/**
 * The sanitized trace for a report, or undefined. A trace is a diagnostic; a
 * failure to build one must never become a failure of the response or the
 * settle it was meant to describe.
 */
function traceOf(rec) {
  try {
    return rec ? rec.build() : undefined;
  } catch (e) {
    log(`trace build failed: ${e.message}`);
    return undefined;
  }
}

const hpSettleHost = pinHpHost(process.env.SETTLE_HOST);
const hpPassthroughHost = pinHpHost(process.env.PASSTHROUGH_HOST);

const cfg = {
  inboundPort: Number(process.env.INBOUND_PORT || 8443),
  // Second inbound port for the api.ppq.ai path: same TLS server, but each
  // connection starts with a PROXY protocol header (v1 or v2) naming the client
  // (proxyListener.mjs). 0 = no such port; the 443 path never uses it.
  ppPort: Number(process.env.PP_PORT || 0),
  orPort: Number(process.env.OR_PORT || 9443),
  settlePort: Number(process.env.SETTLE_PORT || 9444),
  orHost: process.env.OPENROUTER_HOST || 'openrouter.ai',
  // Anthropic's own host for count_tokens (#275); overridable for tests only.
  anthropicHost: process.env.ANTHROPIC_HOST || 'api.anthropic.com',
  // Both horse-power names are PINNED to the measured allowlist in hpHosts.mjs
  // (Oct 17-19 security reports): the parent names which of the listed hosts,
  // never an arbitrary one. A name outside the list leaves the arm unset, which
  // fails closed (authorize 503, no settle, no proxy) and is reported on
  // /health under `hp_hosts`. Resolved above `cfg` so the boot log can say so.
  settleHost: hpSettleHost.host,
  settleSecret: process.env.ENCLAVE_SETTLE_SECRET || '',
  // Answer repeats of hp's balance backoff (429 `balance_backoff`) locally for
  // the Retry-After hp named, instead of asking hp again (hp #1022). Off only
  // for diagnosis; `0` disables.
  localBalanceBackoff: process.env.LOCAL_BALANCE_BACKOFF !== '0',
  // Host/SNI horse-power is addressed by for routes the enclave does not serve
  // itself (api.ppq.ai once that name terminates here). Empty = no proxy: an
  // unknown route is a 404, exactly as before. Reaches horse-power over the
  // settle tunnel, so only the Host header differs from a settle call.
  passthroughHost: hpPassthroughHost.host,
  safetySecret: process.env.SAFETY_IDENTIFIER_SECRET || '',
  // Tinfoil's confidential router (#210): a measured constant, not an env
  // override — see TINFOIL_HOST in tinfoil.mjs for why.
  tinfoilHost: TINFOIL_HOST,
  tlsKeyPath: process.env.TLS_KEY_PATH || '/app/tls/key.pem',
  tlsCertPath: process.env.TLS_CERT_PATH || '/app/tls/cert.pem',
};

// The OpenRouter API key is injected at boot by boot.sh after an
// attestation-gated KMS Decrypt. It never touches disk on the parent.
/** Per worker: credentials hp has put in balance backoff, for hp's window. */
const balanceBackoff = createBalanceBackoff();

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
  // us-west-2: the ONLY mantle region serving GPT-6 Astra (model card + probe
  // 2026-09-10 — 404 not_found from both east regions).
  'bedrock-mantle.us-west-2.api.aws': Number(process.env.BEDROCK_USW2_PORT || 0),
  'api.anthropic.com': Number(process.env.ANTHROPIC_PORT || 0),
  'aiplatform.googleapis.com': Number(process.env.VERTEX_PORT || 0),
  // Tinfoil's router (#210). Keyed by the configured host so hp's candidate
  // (which names the same host) finds the tunnel.
  [cfg.tinfoilHost]: Number(process.env.TINFOIL_PORT || 0),
  'api.venice.ai': Number(process.env.VENICE_PORT || 0),
  // Fireworks on Microsoft Foundry: Fireworks' stack behind an Azure
  // resource hostname, billed to the Azure subscription.
  [FOUNDRY_HOST]: Number(process.env.FOUNDRY_PORT || 0),
  // Legacy provider-name fallback (pre-host-keyed hp payloads).
  openrouter: cfg.orPort,
  fireworks: Number(process.env.FIREWORKS_PORT || 0),
  venice: Number(process.env.VENICE_PORT || 0),
  foundry: Number(process.env.FOUNDRY_PORT || 0),
};
const UPSTREAM_KEYS = {
  openrouter: OPENROUTER_API_KEY,
  fireworks: process.env.FIREWORKS_API_KEY || '',
  anthropic: process.env.ANTHROPIC_API_KEY || '',
  tinfoil: process.env.TINFOIL_API_KEY || '',
  venice: process.env.VENICE_API_KEY || '',
  foundry: process.env.FOUNDRY_API_KEY || '',
};
// Tinfoil's attestation service, a control-plane tunnel: one bundle fetch per
// attestation TTL (or per router key rotation), never per request.
const TINFOIL_ATC_PORT = Number(process.env.TINFOIL_ATC_PORT || 0);

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

// Tinfoil's verified HPKE key for Class B requests (#210, tinfoil.mjs): the
// bundle is fetched from ATC through its tunnel and verified in here, offline.
// Lazy: nothing is fetched until the first private/* request asks, and a
// failure only ever costs that request (there is no fallback for it, by design).
const tinfoilAttestor = createTinfoilAttestor({
  enclaveHost: cfg.tinfoilHost,
  atcPort: TINFOIL_ATC_PORT,
  log,
});
// The unverified bundle `/private/attestation` relays to Class A clients:
// cached and single-flight, so that unauthenticated route costs one ATC fetch
// per TTL, not one per request.
const tinfoilBundleCache = createBundleCache({
  enclaveHost: cfg.tinfoilHost,
  atcPort: TINFOIL_ATC_PORT,
});

// PII detector for requests that opt into `pii_redaction` (pii/attestedDetector.mjs):
// the Tinfoil-hosted filter, through its own tunnel, with the KMS-held Tinfoil
// key. Every call first verifies the detector's attestation against the
// placement's measured config repo (bundle from ATC through its tunnel,
// verified in here) and seals the text to the attested key; a failed
// verification fails the request closed. The host is the measured placement
// host; PII_DETECTOR_HOST exists only so tests can point it at a fake —
// boot.sh never sets it and the init blob cannot. null when the tunnel, the
// ATC tunnel or the key is missing: a pii_redaction request then fails closed
// (503) and no other request is affected.
const PII_PLACEMENT = DETECTOR_PLACEMENTS['tinfoil-hosted'];
const piiDetectorHost = process.env.PII_DETECTOR_HOST || PII_PLACEMENT.host;
const piiDetectorAttestor = createTinfoilAttestor({
  enclaveHost: piiDetectorHost,
  atcPort: TINFOIL_ATC_PORT,
  configRepo: PII_PLACEMENT.configRepo,
  log,
});
const piiDetector = (() => {
  const port = Number(process.env.PII_DETECTOR_PORT || 0);
  if (!port || !UPSTREAM_KEYS.tinfoil || !TINFOIL_ATC_PORT) return null;
  const t = Number(process.env.PII_DETECTOR_TIMEOUT_MS);
  return createAttestedDetector({
    kind: 'tinfoil-hosted',
    url: `https://${piiDetectorHost}${PII_PLACEMENT.path}`,
    apiKey: UPSTREAM_KEYS.tinfoil,
    fetch: createTunnelFetch({ tunnels: { [piiDetectorHost]: port } }),
    timeoutMs: Number.isFinite(t) && t > 0 ? t : PII_DEFAULT_TIMEOUT_MS,
    attestor: piiDetectorAttestor,
  });
})();

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
// What this process presents by default and signs with, following the issued
// certificate once one is installed (servedIdentity.mjs, #195). Created in
// start()/workerMain() once the boot pair is read; null until then.
let servedIdentity = null;
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

// A horse-power name outside the measured allowlist is the one init value this
// image refuses outright; say so at boot (the enclave console needs
// --debug-mode, so /health carries the same fact for production).
for (const [arm, pin] of [['settle_host', hpSettleHost], ['passthrough_host', hpPassthroughHost]]) {
  if (pin.status === 'rejected') {
    log(`${arm} REFUSED: ${JSON.stringify(pin.rejected)} is not in enclave/src/hpHosts.mjs; the arm stays unset (fail closed)`);
  }
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

// Oct 17-19 security reports (andzis, GHSA-33j5-hgc8-9mgg F-01): a JSON.parse
// SyntaxError quotes the text it choked on, so returning `e.message` to the
// client echoed a fragment of the body — for an EHBP request a fragment of
// the sealed plaintext, sent back unsealed. The client now gets a constant;
// our own messages ('payload too large', 'EHBP not initialised') quote
// nothing from the body and still go through. log() keeps the detail.
const UNREADABLE_BODY_MESSAGE = 'request body is not valid JSON';
function unreadableBodyMessage(e) {
  return e instanceof SyntaxError ? UNREADABLE_BODY_MESSAGE : e.message;
}

function sendJson(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
  res.end(body);
}

/**
 * The response headers an authorize refusal carries to the client. hp sets
 * `Retry-After` on its 429s (the per-credential limiter and the balance
 * backoff, hp #1022); the SDKs slow down only when they see it, so it is the
 * one authorize header relayed. Status and body were always relayed.
 */
function authRefusalHeaders(auth) {
  return auth?.retry_after ? { 'retry-after': String(auth.retry_after) } : {};
}

/** Seconds a client is told to wait before retrying a transient refusal. */
const DIRECT_ONLY_RETRY_AFTER_SECONDS = 5;

/**
 * Statuses the terminal OpenRouter candidate is retried on, once. A 429 or a
 * 503 is a moment on one provider or one endpoint, and OpenRouter routes the
 * retry elsewhere more often than not: the old client-side fallback re-sent
 * the same request in the clear and usually succeeded, which hid these.
 * Since PPQdotAI #2824 nothing is re-sent outside the enclave, so the one
 * retry lives here, before the status is passed through as the answer.
 * Nothing has streamed by then; the retry sends the same bytes.
 */
export const RETRIED_UPSTREAM_STATUSES = Object.freeze([429, 503]);
/** The pause before that retry when the upstream names none. */
export const UPSTREAM_RETRY_DELAY_MS = 500;
/** The longest the upstream's Retry-After is honoured; past this the answer is passed through. */
export const UPSTREAM_RETRY_MAX_DELAY_MS = 2_000;

/**
 * How long to wait before the one retry, or null when the upstream asks for
 * longer than a user would wait. Both `Retry-After` forms are read (RFC 9110:
 * delay-seconds or an HTTP-date); a value in neither form gets the default.
 */
export function upstreamRetryDelayMs(retryAfter, now = Date.now()) {
  if (retryAfter === undefined || retryAfter === null || retryAfter === '') return UPSTREAM_RETRY_DELAY_MS;
  const text = String(retryAfter).trim();
  let ms;
  if (/^\d+$/.test(text)) {
    ms = Number(text) * 1000;
  } else {
    const at = Date.parse(text);
    if (Number.isNaN(at)) return UPSTREAM_RETRY_DELAY_MS;
    ms = Math.max(0, at - now);
  }
  return ms > UPSTREAM_RETRY_MAX_DELAY_MS ? null : ms;
}

/**
 * Discard an upstream response body. A body the upstream cuts off emits
 * `error` on the response; with no listener that would take the worker down
 * for an answer nobody is reading.
 */
function drain(upRes) {
  upRes.on('error', () => {});
  upRes.resume();
}

/**
 * A locally-authored refusal for a direct-only model (directOnly.mjs), in the
 * OpenAI error shape hp uses for the same case. `Retry-After` only where a
 * retry can help: a client told to retry a 400 or a 404 never succeeds.
 */
function sendDirectOnlyRefusal(res, refusal) {
  const headers = { 'content-type': 'application/json' };
  if (refusal.status === 429 || refusal.status === 503) {
    headers['retry-after'] = String(DIRECT_ONLY_RETRY_AFTER_SECONDS);
  }
  res.writeHead(refusal.status, headers);
  res.end(JSON.stringify({ error: { message: refusal.message, type: refusal.type, code: refusal.code } }));
}

/**
 * Authorize the caller with horse-power BEFORE spending the company OpenRouter
 * key. Forwards only the cleartext auth headers + model (never query content).
 * horse-power validates the API key / credit_id and checks balance, and returns
 * the resolved credit_id + api_key_id used for settlement. Resolves to
 * { ok, status, body, credit_id, api_key_id }.
 *
 * `clientIp` is the address the PROXY-protocol listener attached to the
 * socket (api port only); with the settle secret set it travels as the MAC'd
 * `x-ppq-client-ip` pair hp verifies (utils/clientIp.ts). Never a header the
 * client sent: authorizeHeaders() copies an allow-list, nothing else.
 */
/**
 * @param {object} [opts]
 * @param {boolean} [opts.localBalanceBackoff=true]  honour the enclave's memory
 *   of hp's balance backoff for this call (lookup before, remember after).
 *   Off for a call hp itself exempts from the balance gate — count_tokens is
 *   no-spend and hp authorizes it on credential and model alone — so a
 *   credential held for chat is never refused here for something hp would
 *   allow. Explicit per call on purpose: a future no-spend intent cannot be
 *   backed off by accident.
 * @param {boolean} [opts.piiRedaction=false]  the request opted into
 *   `pii_redaction`: hp then checks (and holds) the detector fee on top of
 *   the input, free models included, since the settle bills it. Sent only
 *   when true, so every other authorize body is unchanged.
 */
function authorizeWithHorsepower(reqHeaders, model, maxTokens, inputBytes, inputMeasure, clientIp, requestId, opts = {}) {
  // `settleId`: this request's own settle id (minted per request, the settle's
  // idempotency key). Sent at authorize so horse-power can key the balance
  // hold it takes there (horse-power #1046) on an id the enclave chose, not
  // on the caller's `x-request-id`, and release it exactly when this
  // request's settle or terminal error report arrives. Absent on the paths
  // that never settle (count_tokens).
  // `n`: the number of completions the chat body asks for (OpenAI `n`), so hp
  // sizes the hold for n * max_tokens rather than one completion. Sent only
  // when it would change the bound (an integer above 1); older hp ignores it,
  // and applySpendCap bounds it enclave-side against the cap hp answers with.
  const { localBalanceBackoff = true, settleId, n, piiRedaction = false } = opts;
  return new Promise((resolve) => {
    if (!cfg.settleHost) {
      // No horse-power reachable — fail closed, do not spend the key.
      // No settle host is the same class as an unreachable one for telemetry.
      return resolve({ ok: false, status: 503, failure: 'unreachable', body: { error: 'authorization unavailable' } });
    }
    // A credential hp put in balance backoff is answered here for the window
    // hp named (hp #1022): the same 429 and body, no round trip, and — at the
    // caller's `!auth.ok` site — no error report, since nothing failed. hp
    // would not re-read the balance inside its own window either, so a top-up
    // is noticed at the same moment. `backoff` marks it for the caller.
    const credentialKey =
      cfg.localBalanceBackoff && localBalanceBackoff ? presentedCredentialKey(reqHeaders) : null;
    if (credentialKey) {
      const held = balanceBackoff.lookup(credentialKey);
      if (held) {
        return resolve({ ok: false, status: held.status, body: held.body, retry_after: held.seconds, backoff: true, local: true });
      }
    }
    // hp bounds the INPUT cost before the upstream is paid (capping only the
    // output would bound the wrong half of the bill). `input_tokens_o200k` plus
    // the media sizes are the precise inputs (#171); hp applies the per-family
    // factor. `input_bytes` stays for hp builds that predate them, and as hp's
    // fallback whenever the count is absent (text too large, tokenizer missing).
    const payload = JSON.stringify({
      model,
      max_tokens: maxTokens,
      ...(typeof settleId === 'string' && settleId ? { settle_id: settleId } : {}),
      ...(Number.isInteger(n) && n > 1 ? { n } : {}),
      ...(piiRedaction === true ? { pii_redaction: true } : {}),
      input_bytes: Number.isFinite(inputBytes) ? inputBytes : undefined,
      ...(inputMeasure ?? {}),
    });
    // Credentials (authorization / x-api-key / x-credit-id — hp parses all
    // three with the same precedence as /chat/completions), x-query-source,
    // and x-ppq-intent (lets the browser declare a conversation-title request
    // so hp can bill it to PayPerQ rather than the user, horse-power
    // titleIntent.ts; forwarded, not interpreted: hp caps the model and output
    // length, which is what makes the header safe to accept from a client).
    // Plus the enclave's own MAC'd client address when the socket has one, and
    // the request's resolved correlation id as `x-request-id`.
    const headers = authorizeHeaders(reqHeaders, {
      host: cfg.settleHost,
      bodyLength: Buffer.byteLength(payload),
      clientIp,
      secret: cfg.settleSecret,
      requestId,
    });
    // The PII gate on proxied routes names the request it is about to forward
    // (passthrough.mjs), so authorize and the signed count share one id.
    if (requestId) headers['x-request-id'] = requestId;

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
          // hp's 429s name a wait (header first; its body field is the
          // fallback for a hop that stripped the header). A balance backoff is
          // also remembered so the next repeat is answered above.
          const retryAfter = ok ? null : retryAfterSeconds(resp.headers['retry-after'], body?.retry_after_seconds);
          const backoff = !ok && isBalanceBackoffRefusal(resp.statusCode, body);
          if (backoff && credentialKey && retryAfter) {
            balanceBackoff.remember(credentialKey, { seconds: retryAfter, body });
          }
          resolve({
            ok,
            status: resp.statusCode || 502,
            body,
            retry_after: retryAfter,
            backoff,
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
            // The `:online` suffix hp peeled off resolved_model (hp #1055).
            // Absent on older hp → false, and no search is added.
            web_search: body.web_search === true,
            // PPQ's Auto Router allow-list (#790). Absent on older hp → null,
            // and applyAutoRouterConfig injects nothing. Shape-checked rather
            // than passed through: a malformed body must not become a plugin
            // OpenRouter rejects, and a missing allow-list is safer than a
            // half-formed one.
            auto_router: parseAutoRouter(body.auto_router),
            // OpenRouter quality floor (hp #997). Absent on older hp → null,
            // and applyProviderFloor leaves the body untouched.
            provider_floor: parseProviderFloor(body.provider_floor),
            // Smart-routing tier tables + classifier config for autoclaw/* and
            // autorouter/* (hp autoclawDirective.ts). Absent on older hp or for
            // any other model → null; a smart-routing request then 400s below.
            autoclaw: parseAutoclawDirective(body.autoclaw),
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
    // `failure` names the transport outcome so the caller can report
    // authorize_timeout / authorize_unreachable rather than lumping both in
    // with hp's own refusals (authorize_rejected).
    let timedOut = false;
    const onTimeout = () => {
      timedOut = true;
      r.destroy(new Error('authorize timeout'));
    };
    r.setTimeout(AUTHORIZE_TIMEOUT_MS, onTimeout);
    // setTimeout above only fires on socket INACTIVITY, so a peer trickling
    // bytes would hold this open past the bound. Independent hard deadline,
    // the same pattern reportEnclaveError uses.
    const deadline = setTimeout(onTimeout, AUTHORIZE_TIMEOUT_MS);
    r.on('close', () => clearTimeout(deadline));
    r.on('error', (e) => {
      log(`authorize error: ${e.message}`);
      resolve(
        timedOut
          ? { ok: false, status: 504, body: { error: 'authorization timed out' }, failure: 'timeout' }
          : { ok: false, status: 502, body: { error: 'authorization failed' }, failure: 'unreachable' },
      );
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

// The thin path check and transparent proxy for everything else (passthrough.mjs).
// Built once per process; `handle` runs per REQUEST so a keep-alive connection
// can carry a proxied /v1/models and then an in-enclave chat call.
const passthrough = cfg.passthroughHost
  ? createPassthrough({
      host: cfg.passthroughHost,
      port: cfg.settlePort,
      servername: cfg.passthroughHost,
      secret: cfg.settleSecret,
      log,
      onEvent: (code, fields) => reportEnclaveError(code, fields),
    })
  : null;

// Durable retry queue: submit() tries once, then retries transient failures with
// exponential backoff until horse-power acks. Settlement is idempotent, so a
// retry after a slow/lost success is a harmless no-op. See settleQueue.mjs.
const settleQueue = createSettleQueue({
  post: settlePostOnce,
  log,
  // A settle the queue will never deliver is revenue lost silently unless
  // something says so. Identifiers only, plus the trace the settle carried;
  // never the served model (it came from the upstream's own response frames).
  onPermanentFailure: (meta) => {
    counters.settlePermanentFailure();
    reportEnclaveError(ERROR_CODES.SETTLE_FAILED_PERMANENT, {
      request_id: meta?.request_id,
      // The settle's own id; never terminal — this is bookkeeping, not a query outcome.
      settle_id: meta?.settle_id,
      terminal: false,
      credit_id: meta?.credit_id,
      provider: meta?.provider,
      query_source: meta?.query_source,
      trace: meta?.trace,
    });
  },
});

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
  // One per report SENT, counted before the settle-host check so /health sees
  // it even when nothing can be delivered. NOT the request's outcome: a
  // request may send several reports (see counters.mjs); its one outcome is
  // recorded by the request-local `finalize` in handleChatCompletion.
  counters.errorReport(code);
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

/**
 * Counts the request and guarantees it records exactly one outcome on /health
 * (counters.mjs): `finalize` is handed to the handler, which calls it on every
 * early return and at the terminal stream end; an unanticipated throw is the
 * one terminal the handler cannot name itself, so it is named here.
 */
async function handleChatCompletion(req, res) {
  const finalize = counters.beginRequest();
  // Filled in by chatCompletion as soon as each value exists, so an
  // unanticipated throw can still be reported with its id and trace.
  const ctx = {};
  try {
    await chatCompletion(req, res, finalize, ctx);
  } catch (e) {
    finalize(ERROR_CODES.INTERNAL_ERROR);
    if (e && typeof e === 'object') {
      e.reportFields = handlerFailureFields(ctx, ctx.traceRec ? traceOf(ctx.traceRec) : undefined);
    }
    throw e;
  }
}

async function chatCompletion(req, res, finalize, ctx = {}) {
  // The CLIENT's correlation id: echoed on receipts, error reports and the
  // metadata row (the frontend looks a column's price up by it). It is NOT the
  // billing idempotency key — it was, and a caller who reused one header value
  // got every request after the first served and never billed (proved live
  // 2026-09-10). The key hp claims is `settleId`, minted here per request.
  // Bounded once for every egress (trace.mjs resolveRequestId): the caller's
  // id only in the accepted shape, else one minted here.
  const { requestId, fromClient: requestIdFromClient } = resolveRequestId(req.headers['x-request-id']);
  const settleId = randomUUID();
  ctx.requestId = requestId;
  ctx.settleId = settleId;

  // Content-free trace of what happens to this request (trace.mjs): timings,
  // byte counts, the route decision, how the stream ended. Rides the settle
  // body and any error report from here on. Header-derived facts plus the
  // body's routing SHAPE (describeRequestShape — names, counts, routing
  // directives; never content). The recorder never holds the body itself, and
  // build() bounds every field.
  const traceRec = createTraceRecorder();
  traceRec.setClient({
    requestId: req.headers['x-request-id'],
    userAgent: req.headers['user-agent'],
    clientIp: req.socket?.clientIp,
  });
  ctx.traceRec = traceRec;
  traceRec.setEnclave({
    version: ENCLAVE_VERSION,
    worker: cluster.isWorker ? cluster.worker.id : 0,
    box: ENCLAVE_BOX_ID || undefined,
  });

  // The client went away. ONE listener for the whole request, registered
  // before the first await, as relayDialectRequest and decisionsRequest do.
  // Until the Oct 17-19 security reports (Kickpy) it was registered only once
  // the upstream stream was wired up, some four awaits in (body read, input
  // measure, authorize, upstream connect). `close` is a one-shot event: a
  // client that hung up during authorize or the upstream handshake had
  // already emitted it, nothing heard, `clientGone` stayed false, and the
  // request ran to completion for nobody -- the provider billed PPQ for the
  // whole generation and the customer was settled for output they never
  // received. Now:
  //   - before an upstream is chosen, the loop below sees `clientGone` and
  //     abandons the request (terminal client_abort report, nothing settles,
  //     exactly as the retry-pause check already did);
  //   - once the stream is wired, `onClientGone` cancels the upstream and
  //     files the non-terminal report; the cancelled upstream then settles
  //     from what was delivered (settleNow). `abortableUpRes` is set in the
  //     same synchronous block as the stream's 'error' handler, never earlier,
  //     so a destroy can never raise an unhandled 'error' on the response.
  // `close` also follows a normal `res.end()`; `settled` / `writableFinished`
  // make it a no-op then.
  let clientGone = false;
  let settled = false;
  let abortableUpRes = null;
  let onClientGone = null;
  // Set once a redacted answer could not be restored (failRestore): the enclave
  // cut the client off itself, so the close that follows is not a client
  // abort; the upstream is still drained and settled, and nothing more is written.
  let restoreFailed = false;
  res.on('close', () => {
    if (settled || res.writableFinished || restoreFailed) return;
    clientGone = true;
    traceRec.setStreamEnd('client_abort');
    finalize(ERROR_CODES.CLIENT_ABORT);
    if (abortableUpRes) abortableUpRes.destroy(new Error('client aborted; upstream cancelled'));
    if (onClientGone) onClientGone();
  });

  // Auth material travels in cleartext headers (never the body).
  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  if (!creditId && !authHeader) {
    // Not an error code (nothing to report to hp — there is no caller to tie
    // it to), but still this request's outcome.
    finalize('unauthenticated');
    return sendJson(res, 401, {
      error: { message: 'Missing x-credit-id, Authorization or x-api-key', code: 401 },
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
    // e.message stays in log() — it can quote the body it failed to parse;
    // the client gets unreadableBodyMessage(e).
    log(`request unreadable: ${e.message}`);
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      query_source: req.headers['x-query-source'] === 'ui' ? 'ui' : 'api',
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendJson(res, 400, { error: { message: unreadableBodyMessage(e), code: 400 } });
  }

  // Two booleans about the envelope, not the contents: whether the body came
  // HPKE-sealed, and whether the caller asked for a stream (the default).
  traceRec.setEhbp(ehbpCtx !== null);
  traceRec.setStreaming(payload?.stream !== false);
  if (ehbpCtx !== null) counters.ehbp();
  if (payload?.stream !== false) counters.streaming();
  // Routing shape of the body AS THE CLIENT SENT IT — before resolution, the
  // spend cap, or any transform (trace.mjs describeRequestShape: member names,
  // counts, routing directives; never content). hp #997.
  traceRec.setRequestShape(describeRequestShape(payload));

  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  // `pii_redaction`, by value (pii/pipeline.mjs): removed here whenever it is
  // present, so no upstream ever sees it (hp is told only `true`, at authorize,
  // to check the detector fee); `false` means no redaction,
  // `true` runs the sandwich below, anything else is a 400. Absent leaves the
  // body exactly as it was.
  const piiFlag = takePiiFlag(payload);
  if (piiFlag === 'invalid') {
    finalize(PII_ERRORS.INVALID);
    return sendJson(res, 400, piiErrorBody(PII_ERRORS.INVALID));
  }
  const piiOn = piiFlag === 'on';

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
    const code = classifyModelRejection(e.message);
    reportEnclaveError(code, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(code);
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }
  // A private/* body is sealed to Tinfoil past this point, so it cannot be
  // redacted here: refused before any spend rather than served unprotected.
  if (piiOn && isPrivateModel(payload.model)) {
    finalize(PII_ERRORS.UNSUPPORTED_MODEL);
    return sendJson(res, 400, piiErrorBody(PII_ERRORS.UNSUPPORTED_MODEL));
  }

  // Gate on horse-power authorization BEFORE spending the company key. This
  // authenticates the caller (API key or credit_id) and checks balance; without
  // it, anyone reaching the enclave could get free inference on the shared key.
  // It ALSO returns the resolved upstream model slug (+ derived provider pin),
  // so we authorize BEFORE transformPayload and apply the resolution below (#2).
  // Counts only — never content. Also echoed on the settle record so hp can
  // calibrate its per-family factors against the billed input_tokens.
  const inputMeasure = await measureInput(payload);
  const auth = await authorizeWithHorsepower(
    req.headers,
    payload.model,
    payload.max_tokens ?? payload.max_completion_tokens,
    // Size of the messages and tool definitions we are about to forward — the
    // fallback bound for hp builds (or requests) without a token count, so it
    // covers the same input measureInput does. Never billing input.
    (() => {
      try {
        // UTF-8 BYTES, as the field name says: `.length` counts UTF-16 units,
        // which under-counts non-Latin text (CJK is 3 bytes a character).
        const messagesSize = Buffer.byteLength(JSON.stringify(payload.messages ?? []));
        return Array.isArray(payload.tools)
          ? messagesSize + Buffer.byteLength(JSON.stringify(payload.tools))
          : messagesSize;
      } catch {
        return undefined;
      }
    })(),
    inputMeasure,
    // Set only by the PROXY-protocol listener on the api port; undefined on
    // the 443 path and for anything a client could put in a header.
    req.socket?.clientIp,
    requestId,
    { settleId, n: payload.n, piiRedaction: piiOn },
  );
  traceRec.mark('authorized');
  if (!auth.ok) {
    // No model: the only value available here is the raw body's, hp has not
    // canonicalized it yet, and hp already knows which model it just refused.
    // (It is also not the `model` const — that is declared below, so naming it
    // here would be a temporal dead zone ReferenceError on every
    // insufficient-credit request.)
    //
    // Three codes, not one: hp refusing (rejected) is a fact about the caller;
    // hp unreachable or silent is a fact about us, and the two used to be
    // indistinguishable from an insufficient-credit 402 on the report side.
    const code =
      auth.failure === 'timeout'
        ? ERROR_CODES.AUTHORIZE_TIMEOUT
        : auth.failure === 'unreachable'
          ? ERROR_CODES.AUTHORIZE_UNREACHABLE
          : ERROR_CODES.AUTHORIZE_REJECTED;
    // A balance backoff (hp #1022) is the system working as designed, at the
    // volume that buried real failures: not reported, only counted.
    if (!auth.backoff) {
      reportEnclaveError(code, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        upstream_status: auth.status,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    finalize(code);
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    }, authRefusalHeaders(auth));
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;
  // From here an unanticipated throw is reported against the billed account.
  ctx.creditId = billedCreditId;
  ctx.apiKeyId = billedApiKeyId;
  ctx.querySource = querySource;

  // The client left before an upstream was chosen: nothing was served, so
  // nothing settles (as for every failure before an upstream is chosen); the
  // terminal client_abort report is the one trace the request leaves. Shared
  // by the post-authorize check here, the per-candidate check in the loop and
  // the retry pause, which were three places only the last of which looked.
  // PII redaction state (set further down, once the payload is redacted).
  // Detector calls spent on a request that ends with no settle are not billed
  // (developer decision); they are counted and reported so the cost is visible.
  let piiMapping = null;
  let piiCalls = 0;
  const piiUnbilledCalls = () => {
    if (!piiMapping) return undefined;
    counters.piiUnbilled(piiCalls);
    return piiCalls;
  };
  const abandonBeforeUpstream = (provider, upstreamStatus, skipped, failed) => {
    log(`request abandoned before upstream: client gone${provider ? ` (next: ${provider})` : ''}`);
    traceRec.setStreamEnd('client_abort');
    if (skipped || failed) traceRec.setRoute({ skipped: skipped ?? [], failed: failed ?? [] });
    reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: ctx.model,
      provider,
      upstream_status: upstreamStatus,
      pii_redaction_calls: piiUnbilledCalls(),
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.CLIENT_ABORT);
  };
  if (clientGone) return abandonBeforeUpstream(undefined, undefined);

  // The model string the CLIENT sent, kept before anything rewrites it. Two
  // things below must be judged on this and not only on what hp resolves:
  // the family binding (an hp that resolved `anthropic/x` to `vendor/x` first
  // would otherwise pass the map) and the receipt's `requested_model`, which
  // is documented as the caller's string and was hp's until v3 (Oct 17-19
  // security reports: roolzer, Mohammad Said, Bron Zeee).
  const clientModel = typeof payload.model === 'string' ? payload.model : null;

  // Apply hp's model resolution (#2) to the neutral payload. Falls back to the
  // raw model when hp didn't resolve it (older hp). Applies to BOTH paths.
  const modelResolvedByHp =
    typeof auth.resolved_model === 'string' && !!auth.resolved_model;
  if (modelResolvedByHp) {
    payload.model = auth.resolved_model;
  }
  // Smart routing (autoclaw/*, autorouter/*): hp echoes the routing slug as
  // resolved_model and sends the tier tables instead; the enclave classifies
  // the decrypted prompt (smartRouting.mjs) and swaps in the tier's model
  // before transform/upstream selection, exactly where hp's own path does.
  // No directive (older hp) → the 400 this proxy always gave these models.
  let smartRoute = null;
  if (isSmartRoutingModel(payload.model)) {
    if (!auth.autoclaw) {
      const code = ERROR_CODES.MODEL_REJECTED_SMART_ROUTING;
      log('model rejected: smart routing without an autoclaw directive');
      reportEnclaveError(code, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
      finalize(code);
      return sendJson(res, 400, {
        error: { message: 'Smart-routing models are not supported by this horse-power build', code: 400 },
      });
    }
    smartRoute = decideSmartRoute(auth.autoclaw, payload);
    payload.model = smartRoute.model;
    // Tier and table only: the routing slug itself is caller text (a custom
    // autorouter list is whatever the caller typed).
    log(`smart route: tier=${smartRoute.tier} table=${smartRoute.profile} confidence=${smartRoute.confidence.toFixed(2)}`);
  }
  const model = payload.model;
  // Only a slug hp resolved against the live catalog is safe to report. When hp
  // does not resolve (older build), `model` is still the raw string from the
  // decrypted body — caller-controlled text that has proved nothing about
  // itself, and slug syntax is not a content boundary (`my-password-is-x`
  // passes any such regex). hp re-checks against its catalog too; this keeps
  // the enclave side airtight regardless.
  const reportableModel = modelResolvedByHp ? model : undefined;
  ctx.model = reportableModel;
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
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.FREE_MODEL_UNAUTHORIZED);
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
  // `n` multiplies whatever the per-choice length allows, so it is bounded by
  // the same cap (applySpendCap): the cap is per REQUEST, as the hold is.
  if (auth.max_tokens_cap) {
    const { n } = applySpendCap(payload, auth.max_tokens_cap);
    traceRec.setMaxTokensCap({ applied: true, cap: auth.max_tokens_cap, n });
    if (n !== undefined) log(`spend cap: n bounded to ${n} (cap ${auth.max_tokens_cap})`);
  }

  // `:online` (hp #1055) becomes the `web` plugin here, before the snapshot,
  // so the direct gate, the web-search transforms and isOnline all see it.
  if (auth.web_search) applyWebPluginDirective(payload);

  // Snapshot the NEUTRAL payload (resolved model, no provider/transform) BEFORE
  // shaping the OpenRouter body — the direct path's eligibility gate +
  // projectAllowedFields must run on this untransformed form (transformPayload
  // injects OpenRouter-only fields a direct provider 422s on).
  //
  // PII redaction (`pii_redaction: true`) happens here, after authorize and
  // hp's model resolution, so the snapshot and every body built from it —
  // direct and OpenRouter alike — carry placeholders, never the surfaces.
  // Fail closed: a detector that errors, times out or answers something it
  // cannot read means NOTHING is sent upstream and nothing is settled.
  if (piiOn) {
    // hp may resolve an alias onto a private/* model; that body is sealed to
    // Tinfoil and is not redactable here either.
    if (isPrivateModel(model) || hasTinfoilCandidate(normalizeCandidates(auth.upstreams))) {
      // Authorized, so hp holds a balance reservation (horse-power #1046): reported as
      // terminal so it is released now rather than at the hold's TTL.
      reportEnclaveError(ERROR_CODES.MODEL_REJECTED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        upstream_status: 400,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
      finalize(PII_ERRORS.UNSUPPORTED_MODEL);
      return sendJson(res, 400, piiErrorBody(PII_ERRORS.UNSUPPORTED_MODEL));
    }
    let redacted = null;
    let failure = { reason: 'not_configured' };
    if (piiDetector) {
      const t0 = Date.now();
      try {
        redacted = await redactBody(piiChatDialect, payload, piiDetector);
        counters.piiRedacted({ calls: redacted.calls, texts: redacted.texts, entities: redacted.entities, latencyMs: Date.now() - t0 });
      } catch (e) {
        failure = e;
      }
    }
    if (!redacted) {
      // The reason token only (TIMEOUT, HTTP_STATUS, ...): never text or spans.
      const reason = piiFailureReason(failure);
      log(`pii detector failed: ${reason}`);
      counters.piiFailure(reason);
      reportEnclaveError(ERROR_CODES.PII_DETECTOR_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        query_source: querySource,
        reason,
        trace: traceOf(traceRec),
      });
      finalize(PII_ERRORS.UNAVAILABLE);
      return sendJson(res, 503, piiErrorBody(PII_ERRORS.UNAVAILABLE));
    }
    payload = redacted.body;
    piiMapping = redacted.mapping;
    piiCalls = redacted.calls;
  }
  const basePayload = structuredClone(payload);

  // Shape the OpenRouter body IN PLACE on `payload`: provider_directive +
  // transforms + hp's strips + the OpenAI safety identifier (#657).
  // Keeps the caller's `zdr` on top of the directive (apienz, Oct 17-19 reports).
  applyProviderDirective(payload, auth.provider_directive);
  try {
    transformPayload(payload);
  } catch (e) {
    log(`transform failed: ${e.message}`);
    reportEnclaveError(ERROR_CODES.TRANSFORM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      pii_redaction_calls: piiUnbilledCalls(),
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.TRANSFORM_FAILED);
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }
  // Before the free strip — hp injects the auto-router plugin inside
  // transformPayload, ahead of its own strip, and the strip deletes `plugins`.
  applyAutoRouterConfig(payload, auth.auto_router);
  if (auth.is_free) applyFreeModelStrip(payload);
  if (auth.strip_tools) applyToolStrip(payload);
  applyProviderFloor(payload, auth.provider_floor);
  applySafetyIdentifier(payload, billedCreditId, cfg.safetySecret);
  traceRec.setOrProvider(payload.provider);

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
  const normalized = normalizeCandidates(auth.upstreams);
  // A private/* request that hp did not answer with a Tinfoil candidate (an
  // older hp, a resolution failure) must be refused HERE, before the loop
  // below could take the OpenRouter terminal with a private prompt. The
  // enclave's own rule, not hp's; same code routing.mjs used to raise.
  if (refusesUnroutedPrivate(model, normalized)) {
    reportEnclaveError(ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      pii_redaction_calls: piiUnbilledCalls(),
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH);
    return sendJson(res, 400, {
      error: { message: 'private/* models are not routable on this path yet', code: 400 },
    });
  }
  // The converse: a Tinfoil candidate for a public model is a malformed hp
  // answer (provider substitution + mis-billing if followed). Refused.
  if (refusesMisroutedToTinfoil(model, normalized)) {
    log('authorize answered a non-private model with a tinfoil candidate; refusing');
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      pii_redaction_calls: piiUnbilledCalls(),
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: TINFOIL_PROVIDER,
      upstream_status: 0,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendJson(res, 502, { error: { message: 'upstream routing refused', code: 502 } });
  }
  // A private/* request has exactly one place to go (#210). normalizeCandidates
  // synthesises an OpenRouter terminal for every list so a request always has
  // somewhere to fall; for a private prompt that fall would send the plaintext
  // to a provider the model exists to keep it from. Strip it: a private request
  // that cannot reach Tinfoil fails, it is not answered elsewhere.
  const privateOnly = hasTinfoilCandidate(normalized);
  const candidates = privateOnly ? privateCandidates(normalized) : normalized;

  // Class B: verify Tinfoil's attestation (cached) and seal the projected body
  // to the router's key. An attestation failure is reported by its own code —
  // it is the one skip reason that means "the private path is down", not "this
  // request was not eligible" — and the candidate is skipped, which for a
  // private-only list means the request is refused below.
  const buildTinfoilCandidate = async (cand) => {
    let hpkePublicKeyHex = null;
    try {
      hpkePublicKeyHex = (await tinfoilAttestor.get()).hpkePublicKeyHex;
    } catch (e) {
      log(`tinfoil attestation unavailable: ${e?.message}`);
      reportEnclaveError(ERROR_CODES.TINFOIL_ATTESTATION_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        // Not final: the candidate is skipped and the loop goes on; if nothing
        // else serves, the upstream_unreachable report below is the final one.
        terminal: false,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: TINFOIL_PROVIDER,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    return buildTinfoilRequest({
      candidate: cand,
      basePayload,
      ports: UPSTREAM_PORTS,
      keys: UPSTREAM_KEYS,
      hpkePublicKeyHex,
    });
  };

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
      // A direct-only model (no OpenRouter twin — directOnly.mjs) must not
      // fall through to OpenRouter: it would answer "not a valid model ID"
      // about a model that exists, for a request that failed for some other
      // reason. Every candidate that could serve it has been skipped or has
      // failed by the time the loop reaches here, so answer for what happened.
      const directOnly = directOnlyNamespaceFor(model);
      if (directOnly) {
        const own = candidates.find((c) => c.provider === directOnly.provider);
        const refusal = classifyDirectOnlyRefusal({
          model,
          provider: directOnly.provider,
          skipped: skippedCandidates,
          failed: failedCandidates,
          supportsImages: own?.supports_image_input === true,
        });
        log(`direct-only refusal: ${refusal.code} (${refusal.status})`);
        traceRec.setRoute({ skipped: skippedCandidates, failed: failedCandidates });
        // A 400 is the caller's request, not a fault: counted, not reported.
        // Anything else means the one upstream that could serve this did not.
        const code = refusal.status === 400 ? ERROR_CODES.MODEL_REJECTED : ERROR_CODES.UPSTREAM_UNREACHABLE;
        if (refusal.status !== 400) {
          reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
            request_id: requestId,
            settle_id: settleId,
            terminal: true,
            pii_redaction_calls: piiUnbilledCalls(),
            credit_id: billedCreditId,
            api_key_id: billedApiKeyId,
            model: reportableModel,
            provider: directOnly.provider,
            upstream_status: failedCandidates.find((f) => f.provider === directOnly.provider)?.status ?? 0,
            query_source: querySource,
            trace: traceOf(traceRec),
          });
        }
        finalize(code);
        return sendDirectOnlyRefusal(res, refusal);
      }
      spec = orSpec;
    } else {
      // The candidate's own fields must agree before anything is built or
      // sealed: `provider` (what the settle will say), `host` (which tunnel
      // and TLS name), `key_ref` (which secret goes on the wire) and
      // `api_style` (which builder, so which credential path). hp
      // asserts them independently and nothing here cross-checked them, so
      // `{provider:'fireworks', host:'api.venice.ai', key_ref:'openrouter'}`
      // sent the OpenRouter key to Venice and settled as Fireworks (Oct 17-19
      // security reports: bgsparsiti finding 2, bronzeee F2). Same posture as
      // the family check below: SKIPPED and reported, never fatal.
      const pbind = checkProviderBinding(cand);
      if (!pbind.allowed) {
        // candidateLabel: the fields are parsed JSON from hp, and a template
        // literal over an object with a non-callable toString would throw.
        log(
          `direct ${candidateLabel(cand.provider)} REFUSED: ${pbind.reason} ` +
            `host=${candidateLabel(cand.host)} key_ref=${candidateLabel(cand.key_ref)} ` +
            `api_style=${candidateLabel(cand.api_style)}` +
            (pbind.expected
              ? ` (expected hosts: ${pbind.expected.hosts.join(',')}, key_ref: ${pbind.expected.key_ref}, api_style: ${pbind.expected.api_style})`
              : ''),
        );
        skippedCandidates.push({ provider: cand.provider, reason: pbind.reason, field: pbind.field });
        traceRec.setRoute({ skipped: skippedCandidates, failed: failedCandidates });
        reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
          request_id: requestId,
          settle_id: settleId,
          // Not final: this candidate is skipped and the next one is tried.
          terminal: false,
          credit_id: billedCreditId,
          api_key_id: billedApiKeyId,
          model: reportableModel,
          provider: cand.provider,
          upstream_status: 0,
          query_source: querySource,
          trace: traceOf(traceRec),
        });
        continue;
      }
      // Dispatch on the candidate's wire dialect. 'bedrock' = the OpenAI
      // Responses API on bedrock-mantle (SigV4, plain-SSE response);
      // 'anthropic' = the Messages API on api.anthropic.com (x-api-key,
      // Anthropic SSE); everything else is the OpenAI chat dialect.
      const built = isTinfoilCandidate(cand)
        ? await buildTinfoilCandidate(cand)
        : cand.api_style === 'bedrock'
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
                // #286: per-conversation replica affinity for Fireworks'
                // prompt cache; derived, never logged. Only the Fireworks
                // dialect (direct, and on Foundry) documents the header, so
                // only compute it for those candidates.
                affinity:
                  FIREWORKS_WIRE_PROVIDERS.has(cand.provider)
                    ? computeSessionAffinity(billedCreditId, basePayload.messages)
                    : undefined,
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
        // The build may have awaited (Tinfoil attestation, a Vertex token) and
        // the client hung up meanwhile. With nobody waiting there is no next
        // candidate worth preparing, and when this was the last one the loop
        // would otherwise fall out to the upstream_unreachable report below
        // with the outcome already named client_abort (CodeRabbit on #339).
        if (clientGone) return abandonBeforeUpstream(cand.provider, undefined, skippedCandidates, failedCandidates);
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
      //
      // Judged on BOTH the client's literal and hp's resolved id. hp authors
      // `resolved_model` in the same answer as the candidates, so a check on
      // the resolved id alone constrains nothing hp wants to do; the client's
      // string is the one id it did not write (upstreamBinding.mjs).
      const bind = checkBindings([clientModel, model], spec.opts?.servername);
      if (!bind.allowed) {
        log(
          `direct ${cand.provider} REFUSED: ${BINDING_VIOLATION} ` +
            `${bind.model} -> ${spec.opts?.servername} (permitted: ${bind.permitted.join(',')})`,
        );
        skippedCandidates.push({
          provider: cand.provider,
          reason: BINDING_VIOLATION,
          field: spec.opts?.servername,
        });
        // Reported because a silent refusal is indistinguishable from a
        // provider outage, and this one means hp asked for something it should
        // not have.
        // Route state first, so the trace names the violating candidate even
        // when a later candidate goes on to serve the request.
        traceRec.setRoute({ skipped: skippedCandidates, failed: failedCandidates });
        reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
          request_id: requestId,
          settle_id: settleId,
          // Not final: this candidate is skipped and the next one is tried.
          terminal: false,
          credit_id: billedCreditId,
          api_key_id: billedApiKeyId,
          model: reportableModel,
          provider: cand.provider,
          upstream_status: 0,
          query_source: querySource,
          trace: traceOf(traceRec),
        });
        continue;
      }
    }
    // Nobody is waiting: do not send. A candidate skipped above may have
    // awaited (Tinfoil attestation, a Vertex token), and the client may have
    // hung up during authorize; either way the prompt must not reach a
    // provider that will bill for it.
    if (clientGone) return abandonBeforeUpstream(cand.provider, undefined, skippedCandidates, failedCandidates);
    // The request leaves for an upstream: the origin of time-to-first-token.
    // Only here, after every skip above, so a candidate passed over before
    // sending never sets it; first-write-wins, so the next candidate or the
    // re-attest retry below does not move it and a failed attempt stays
    // inside the window, as it does for the user.
    traceRec.mark('upstreamSent');
    let attempt = await attemptUpstream(spec.opts, spec.bodyStr);
    if (spec.apiStyle === 'tinfoil' && attempt.statusCode === KEY_CONFIG_MISMATCH_STATUS) {
      // The router rotated its HPKE key under a cached attestation: the body
      // was sealed to a key it no longer holds. Refetch, reseal, retry once;
      // a second 422 passes through as the router's own answer.
      log('tinfoil key-config mismatch; re-attesting once');
      if (attempt.res) drain(attempt.res);
      tinfoilAttestor.invalidate();
      tinfoilBundleCache.invalidate();
      const rebuilt = await buildTinfoilCandidate(cand);
      if (clientGone) {
        // The client hung up while the re-attestation fetch was in flight. The
        // 422 said the router could not open the first body, so nothing was
        // served or billed yet; the resealed request would be the first send
        // the router can read, and nobody is waiting for it. Same posture as
        // the retry pause below: record the refused attempt, send nothing.
        failedCandidates.push({ provider: cand.provider, status: attempt.statusCode });
        return abandonBeforeUpstream(cand.provider, attempt.statusCode, skippedCandidates, failedCandidates);
      }
      if (rebuilt.skip) {
        // The drained 422 must not be chosen as a terminal answer (it would
        // hang the client on an empty body): a re-attest that cannot proceed
        // is a failed candidate, and the private request is refused below.
        attempt = { ok: false, statusCode: attempt.statusCode, error: new Error('tinfoil re-attest skipped') };
      } else {
        spec = { ...rebuilt, isDirect: true };
        attempt = await attemptUpstream(spec.opts, spec.bodyStr);
      }
    }
    if (terminal && isOpenRouter(cand) && attempt.res && RETRIED_UPSTREAM_STATUSES.includes(attempt.statusCode)) {
      // The terminal answer would be this status. One retry first (see
      // RETRIED_UPSTREAM_STATUSES); the second answer, whatever it is, is the
      // one passed through. Recorded as a failed candidate so the receipt
      // and the settle trace show the first attempt beside the served one.
      const delay = upstreamRetryDelayMs(attempt.res.headers['retry-after']);
      if (delay === null) {
        log(`upstream openrouter ${attempt.statusCode}: retry-after too long, passing through`);
      } else {
        log(`upstream openrouter ${attempt.statusCode}: retrying once in ${delay} ms`);
        drain(attempt.res); // discard the first answer's body
        failedCandidates.push({ provider: cand.provider, status: attempt.statusCode });
        await new Promise((resolve) => setTimeout(resolve, delay));
        if (clientGone || res.destroyed) {
          // The client hung up during the pause: nothing to answer, and a
          // retry would only bill a request nobody is waiting for. The report
          // names the first attempt the client did not wait out.
          log('upstream retry skipped: client gone');
          return abandonBeforeUpstream(cand.provider, attempt.statusCode, skippedCandidates, failedCandidates);
        }
        attempt = await attemptUpstream(spec.opts, spec.bodyStr);
      }
    }
    if (attempt.res && (attempt.ok || terminal)) {
      chosen = { spec, res: attempt.res, statusCode: attempt.statusCode || 200 };
      traceRec.mark('upstreamHeaders');
      break;
    }
    if (attempt.res) drain(attempt.res); // discard the failed direct response body
    log(`upstream ${cand.provider} failed: ${attempt.statusCode || attempt.error?.message || 'unknown'}`);
    lastFailure = { provider: cand.provider, status: attempt.statusCode };
    failedCandidates.push({ provider: cand.provider, status: attempt.statusCode });
    if (terminal) {
      // Carries WHICH upstream died and with what status — the thing the client
      // cannot see (it only ever gets `enclave returned HTTP 502`) and the
      // reason a provider outage was previously indistinguishable from a bug.
      // The trace carries the skipped/failed lists even with no upstream
      // chosen — with nothing served, WHY is the whole story.
      traceRec.setRoute({ skipped: skippedCandidates, failed: failedCandidates });
      reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        pii_redaction_calls: piiUnbilledCalls(),
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: lastFailure.provider,
        upstream_status: lastFailure.status,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
      finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
      return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
    }
  }
  if (!chosen) {
    // Every candidate skipped or failed, and the client is gone: the close
    // handler already named the outcome client_abort, so the terminal report
    // says so too rather than blaming the private path (nothing was served
    // either way; nothing settles).
    if (clientGone) return abandonBeforeUpstream(lastFailure?.provider, lastFailure?.status, skippedCandidates, failedCandidates);
    traceRec.setRoute({ skipped: skippedCandidates, failed: failedCandidates });
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      pii_redaction_calls: piiUnbilledCalls(),
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: lastFailure?.provider,
      upstream_status: lastFailure?.status,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    // Named as such: a private request has no fallback, so "unreachable" here
    // means the private path itself, not a provider hiccup the next candidate
    // would have covered.
    return sendJson(res, 502, {
      error: {
        message: privateOnly ? 'private model upstream unavailable' : 'upstream unreachable',
        code: 502,
      },
    });
  }

  const chosenDirect = chosen.spec.isDirect;
  const chosenProvider = chosenDirect ? chosen.spec.provider : 'openrouter';
  // The same facts buildReceipt states, in the trace: which upstream served,
  // its validated hostname, and why the candidates ahead of it were not used.
  traceRec.setRoute({
    chosen: chosenProvider,
    upstreamHost: chosen.spec.opts?.servername,
    apiStyle: chosen.spec.apiStyle || 'openai',
    skipped: skippedCandidates,
    failed: failedCandidates,
  });
  counters.provider(chosenProvider);

  // How this request failed, when it failed and still settles: the settle
  // carries it as `failure_code` so the billed row can say so. The first
  // failure wins; a clean answer or a client abort leaves it unset.
  let settleFailureCode;
  // The upstream HTTP status behind a passed-through error, sent as
  // `failure_status` beside it. Set only by the failure that set the code, so
  // the pair always describes the same failure; absent otherwise (never null).
  let settleFailureStatus;

  // A terminal candidate is chosen even when it answered 4xx/5xx — we pass the
  // upstream's error through rather than inventing one. That path still settles,
  // so without this report a provider returning 400 to every request would be
  // completely invisible on our side (Codex review).
  if (chosen.statusCode >= 400) {
    if (settleFailureCode === undefined) {
      settleFailureCode = ERROR_CODES.UPSTREAM_ERROR_STATUS;
      settleFailureStatus = chosen.statusCode;
    }
    reportEnclaveError(ERROR_CODES.UPSTREAM_ERROR_STATUS, {
      request_id: requestId,
      settle_id: settleId,
      // Not final: the passed-through error still streams and settles below.
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: chosenProvider,
      upstream_status: chosen.statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    // The passed-through error IS this request's outcome, even though the
    // body still streams and settles below; the later stream-end finalize is
    // then a no-op.
    //
    // The same has to be true of the TRACE, and it was not. `finalize` is an
    // in-enclave counter: it never crosses the settle. The trace does, and
    // `stream_end` is the only thing in it that names an outcome — hp's
    // `classifyOutcome` (services/telemetry/enclave.ts) switches on nothing
    // else. An upstream 4xx body streams to completion like any other, so
    // `src.on('end')` wrote `clean` and hp filed the request as `status: 'ok'`.
    // Proved live 2026-09-23 against a real OpenRouter 404: the error report
    // carried `upstream_error_status` + `upstream_status: 404` while the
    // settle for the same request said the stream ended cleanly. Named here,
    // at the point the outcome is decided, exactly as the client-abort path
    // does — `setStreamEnd` is
    // first-writer-wins (trace.mjs:293), so the later `end` becomes a no-op.
    traceRec.setStreamEnd('upstream_error');
    finalize(ERROR_CODES.UPSTREAM_ERROR_STATUS);
  }

  const extractor = new CostExtractor({ isFreeModel });
  // What actually went out, for the settle when the usage frame never comes
  // (client abort → upstream cancelled; see outputCount.mjs).
  const outputCounter = new OutputCounter();
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
    if (!buf || buf.length === 0 || restoreFailed) return;
    // Plaintext length on purpose, before any EHBP framing: the number support
    // wants is the size of the answer, and it must mean the same thing for a
    // sealed and an unsealed response.
    traceRec.addBytes(buf.length);
    if (respEnc) {
      writeChain = writeChain.then(async () => res.write(await respEnc.encrypt(buf)));
    } else {
      res.write(buf);
    }
  };

  const upRes = chosen.res;
  // Class B (#210): the router sealed its answer to the key we sent, so it is
  // opened here and the rest of this pipeline — extractor, rewriter, receipt,
  // the EHBP re-seal to a browser — sees the same plaintext chat-completions
  // bytes it sees from every other upstream. The nonce header says whether an
  // answer is sealed, and the router seals its ERROR answers to a sealed
  // request too (a 400 for `tools: []`, a 503 for a retired model), so any
  // answer carrying a nonce is opened, whatever its status (#303): until then
  // a sealed 4xx/5xx was forwarded as ciphertext, the client saw a "garbled"
  // body, and the error-body sanitizer below never saw it. An answer with no
  // nonce is a plaintext error status and passes through as-is.
  let src = upRes;
  if (chosen.spec.apiStyle === 'tinfoil') {
    const nonce = sealedAnswerNonce(upRes.headers);
    const sealed = nonce !== null;
    const served = chosen.statusCode >= 200 && chosen.statusCode < 300;
    if (served && !sealed) {
      // A 2xx from the router is sealed by definition. One without a nonce is
      // not a plaintext answer to pass through — it is bytes this enclave
      // cannot read and must not forward as if it could, nor settle.
      log('tinfoil 2xx without a response nonce; refusing');
      upRes.resume();
      reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        pii_redaction_calls: piiUnbilledCalls(),
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: chosenProvider,
        upstream_status: chosen.statusCode,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
      finalize(ERROR_CODES.STREAM_FAILED);
      return sendJson(res, 502, { error: { message: 'private model response unreadable', code: 502 } });
    }
    if (sealed) {
      try {
        src = decryptedStream(
          upRes,
          await createResponseOpener({ ...chosen.spec.seal, responseNonceHex: nonce }),
        );
      } catch (e) {
        log(`tinfoil response opener failed: ${e.message}`);
        upRes.resume();
        reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
          request_id: requestId,
          settle_id: settleId,
          terminal: true,
          pii_redaction_calls: piiUnbilledCalls(),
          credit_id: billedCreditId,
          api_key_id: billedApiKeyId,
          model: reportableModel,
          provider: chosenProvider,
          upstream_status: chosen.statusCode,
          query_source: querySource,
          trace: traceOf(traceRec),
        });
        finalize(ERROR_CODES.STREAM_FAILED);
        return sendJson(res, 502, { error: { message: 'private model response unreadable', code: 502 } });
      }
    }
  }
  // A passed-through upstream ERROR body is sanitized before anything sees
  // it. OpenRouter's carries its id for PayPerQ's organisation (`user_id`),
  // the provider's name and links to itself — all constant, all readable by
  // any client with one bad model id, and all of what the product hides
  // behind "AI Provider". Wrapped here, after any sealing has been opened and
  // before the extractor/rewriter, so the settle still runs on the same
  // pipeline; see upstreamErrorBody.mjs for what is kept.
  if (chosen.statusCode >= 400) {
    src = sanitizedErrorStream(src, chosen.statusCode);
  }
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
  // Reasoning field parity for a Fireworks-dialect answer (#256; direct or on
  // Foundry, which streams the same `reasoning_content` deltas): mirror the
  // wire `reasoning_content` into OpenRouter's `reasoning` + `reasoning_details`
  // so the route a turn took never changes what the client can show or replay.
  // Sits right after the dialect translators, so the extractor, the counter
  // and the rewriter all see one dialect. Gated on `!translator` explicitly:
  // a translator's finish() tail is fed straight to the extractor below and
  // would bypass the mirror, so the two must never share a response (today
  // no Fireworks candidate has one). A sanitized error body (status >= 400)
  // is never a chat chunk, so it is left alone.
  const reasoningMirror =
    chosenDirect && FIREWORKS_WIRE_PROVIDERS.has(chosen.spec.provider) && chosen.statusCode < 400 && !translator
      ? new ReasoningMirror({
          sse: String(respHeaders['content-type']).includes('text/event-stream'),
        })
      : null;
  // Venice-direct web search: the citation frame is rewritten into the
  // annotations delta every PPQ client reads, and the searches it evidences
  // are counted for the settle (veniceCitations.mjs). Every Venice response
  // gets one — a search is requested per turn, and a response that carries
  // no citations passes through byte for byte. A non-streaming body is held
  // for one rewrite at the end, like the mirror's. Same `!translator` and
  // status gates as the mirror above, for the same reasons.
  const veniceCitations =
    chosenDirect && chosen.spec.provider === 'venice' && chosen.statusCode < 400 && !translator
      ? new VeniceCitationTranslator({
          sse: String(respHeaders['content-type']).includes('text/event-stream'),
        })
      : null;
  if (respEnc) respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
  // Placeholders back to surfaces, on the chat-completions bytes (after any
  // translator, before the extractor/rewriter), so the rebrand, the model
  // rewrite and the client all see restored text. Null when redaction is off.
  // Bounded like the Messages/Responses relay's: what it holds (a whole JSON
  // body, an incomplete event) past the bound fails the answer, never the
  // enclave's memory.
  const piiRestorer = piiMapping
    ? createResponseRestorer(piiChatDialect, piiMapping, respHeaders['content-type'], {
        maxBytes: PII_RESTORE_MAX_BYTES,
      })
    : null;
  const piiRestoreSse = String(respHeaders['content-type']).includes('text/event-stream');
  // A restorer that cannot go on ends the answer as failed: in-band on a
  // stream, a cut connection on JSON (its status is already out). The upstream
  // is still drained and settled; only the client side stops.
  const failRestore = (e) => {
    log(`chat pii restore failed: ${e?.name || 'error'}`);
    settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
    traceRec.setStreamEnd('upstream_error');
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      // Not final: the drained upstream still settles.
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: chosenProvider,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    if (piiRestoreSse) {
      writeOut(Buffer.from('data: ' + JSON.stringify({ error: { message: 'upstream error', code: 502 } }) + '\n\n', 'utf8'));
      restoreFailed = true;
      writeChain.then(() => res.end()).catch(() => res.destroy());
    } else {
      restoreFailed = true;
      res.destroy();
    }
  };

  // The enclave's own statement of where this went (receipt.mjs). Built when
  // it is written, because `served_model` is whatever the upstream's answer
  // has named by then. On a translated direct route (Anthropic Messages,
  // Bedrock Responses) the first chat frame is synthesized by the translator
  // from OUR configured id, so the extractor's first `model` was the enclave's
  // own echo and the receipt could not witness an upstream-side substitution
  // (Oct 17-19 security reports, Refangga AF: "receipt served_model is the
  // enclave's echo on direct routes"). The translator captures the upstream's
  // own echo (message_start.model / response.created.model) before it emits
  // that frame, so the receipt takes it from there; the settle already reports
  // the same echo through the usage frame. Pass-through routes are unchanged.
  const receiptSigningKey = connectionSigningKey(req);
  const receiptNow = () =>
    buildReceipt({
      // The caller's string and hp's resolution of it, separately (v3). Before
      // this both were `model`, which is hp's by the time it is read.
      requestedModel: clientModel ?? model,
      resolvedModel: model,
      spec: chosen.spec,
      statusCode: chosen.statusCode,
      skipped: skippedCandidates,
      failed: failedCandidates,
      requestId,
      requestIdFromClient,
      issuedAt: new Date(),
      servedModel: servedModelReport(translator, extractor.result.model).servedModel,
    });

  // A response that is not an event stream carries the receipt in its headers,
  // which leave before any of the body has arrived: `served_model` is null.
  Object.assign(
    respHeaders,
    signedReceiptHeaders(respHeaders['content-type'], receiptNow(), receiptSigningKey),
  );
  res.writeHead(chosen.statusCode, respHeaders);

  // An event stream carries it as comment lines, through writeOut so they are
  // sealed for EHBP clients, ahead of the first frame (see ReceiptGate).
  const receiptGate = new ReceiptGate({
    carries: canCarryReceipt(respHeaders['content-type']),
  });
  // Every upstream byte reaches the client through here.
  const release = (parts) => {
    for (const part of parts) {
      if (part !== RECEIPT_HERE) {
        traceRec.mark('firstByte');
        writeOut(part);
        continue;
      }
      const receipt = signedReceiptBytes(respHeaders['content-type'], receiptNow(), receiptSigningKey);
      if (receipt) writeOut(receipt);
    }
  };

  // Whether the stream stopped because the max_tokens cap applied above was
  // hit. Detected from the finish reason the upstream states (every dialect
  // reaches this handler as chat-completions SSE, where it is `length`), and
  // only looked for when a cap was applied — a fixed-string test, never a
  // parse of the content.
  const capApplied = Boolean(auth.max_tokens_cap);
  let capHit = false;
  // `finish_reason` can straddle two raw chunks on an untranslated stream, so
  // the check runs over the tail of the previous chunk plus this one.
  let capTail = '';
  // The first frame carrying generated text, looked for on the upstream's own
  // frames (before translation and rewrite) so its time is when the upstream
  // produced it. Only on a served event stream: a JSON body or an error status
  // has no first token, and the trace says null. Stops at the first token.
  const firstToken =
    chosen.statusCode >= 200 &&
    chosen.statusCode < 300 &&
    (translator || String(upRes.headers['content-type'] || '').includes('text/event-stream'))
      ? new FirstTokenDetector()
      : null;
  counters.streamOpened();
  src.on('data', (raw) => {
    if (firstToken && !firstToken.done) {
      const kind = firstToken.feed(raw);
      if (kind) traceRec.markFirstToken(kind);
    }
    let translated = translator ? translator.feed(raw) : raw;
    if (translator && translated.length === 0) return;
    // The counter sees the ORIGINAL deltas: the mirror can triple a line's
    // size, and a line past the counter's MAX_LINE_CHARS is dropped, which
    // would under-bill an aborted stream. Each original chunk is counted here
    // exactly once; the mirror's tail below is never fed to it. With
    // redaction on it counts the placeholder text the upstream generated, not
    // the restored surfaces, as the Messages/Responses relay does.
    outputCounter.feed(translated);
    // Placeholders back to surfaces first, so every stage below (mirror,
    // citations, rewriter) sees the text the client gets. The extractor reads
    // the upstream's own bytes instead, ahead of the restore: usage, cost,
    // model and generation id are never placeholders, and the restorer holds
    // a whole non-stream body back — past its bound it gives up holding the
    // prefix, which would leave the extractor only a suffix it cannot parse.
    if (piiRestorer) {
      extractor.feed(translated);
      if (restoreFailed) return;
      try {
        translated = piiRestorer.push(translated);
      } catch (e) {
        failRestore(e);
        return;
      }
      if (translated.length === 0) return;
    }
    let chunk = reasoningMirror ? reasoningMirror.feed(translated) : translated;
    if (reasoningMirror && chunk.length === 0) return;
    if (veniceCitations) {
      chunk = veniceCitations.feed(chunk);
      if (chunk.length === 0) return;
    }
    if (!piiRestorer) extractor.feed(chunk);
    if (capApplied && !capHit) {
      const text = capTail + chunk.toString('utf8');
      if (/"finish_reason"\s*:\s*"length"/.test(text)) capHit = true;
      capTail = text.slice(-64);
    }
    const out = rewriter.feed(chunk);
    release(receiptGate.feed(out, extractor.result.model));
  });
  // Settle exactly once, from whichever of 'end' / 'error' fires first. An
  // upstream stream error used to skip settlement entirely: the user had the
  // partial answer, and whatever usage the stream had already reported — or,
  // on OpenRouter, the generation id hp can price from — was never sent.
  // (`settled` is declared with the close listener at the top of the handler.)
  const settleNow = () => {
    // A throw from here on is not the request's final word: it is settling.
    ctx.settleStarted = true;
    if (settled) return;
    settled = true;
    traceRec.mark('end');
    counters.streamClosed();
    // The terminal stream end is the outcome (clean / cap_hit / upstream_error
    // / client_abort) — unless an early finalize (a passed-through upstream
    // error status) already named it, in which case this is a no-op. The
    // CLIENT_ABORT / STREAM_FAILED reports count only under error_reports.
    finalize(traceRec.streamEnd());
    const usage = extractor.finish();
    // The usage frame is the authority. When it never came — the client hung
    // up and the upstream was cancelled, or the stream died before it — bill
    // what was delivered: the local o200k count of the deltas that went out,
    // and the authorize-time input measure for the prompt. Without this the
    // settle is 0/0 and megabytes of delivered output go unbilled (2026-09-20:
    // 69 such settles in 5.5 h across two customers). Tokenizing is async, so
    // the settle is sent from a continuation; `settled` is already latched.
    void (async () => {
      let usageSource = 'upstream';
      let inputTokens = usage.inputTokens;
      let outputTokens = usage.outputTokens;
      if (!(outputTokens > 0)) {
        const counted = await outputCounter.finish().catch(() => ({ chars: 0, tokens: 0 }));
        if (counted.tokens > 0) {
          usageSource = 'counted';
          outputTokens = counted.tokens;
        }
      }
      // The prompt was consumed the moment the upstream accepted the request
      // (a 2xx), whether or not a delta ever came back. Until the Oct 17-19
      // security reports this fallback lived inside the `counted.tokens > 0`
      // branch above, so a client that hung up after the upstream's headers
      // but before its first delta -- or a stream that died there -- settled
      // input 0 for a prompt the provider had already billed PPQ for: a
      // repeatable loss, largest on exactly the large prompts whose prefill
      // takes longest. Billed from the authorize-time o200k measure, as an
      // estimate (`usage_source: 'counted'`), only for a served status: an
      // upstream 4xx/5xx passed through still settles 0/0, the visible $0
      // row hp expects for a refused request.
      const served = chosen.statusCode >= 200 && chosen.statusCode < 300;
      if (served && !(inputTokens > 0) && inputMeasure.input_tokens_o200k > 0) {
        usageSource = 'counted';
        inputTokens = inputMeasure.input_tokens_o200k;
      }
      // Class B: the router's trusted usage line (header on JSON, trailer on
      // a stream) is the billing authority — it carries the ATTESTED served
      // model hp keys the charge on. A 2xx with no line is reported: hp then
      // bills the counts from the body fail-closed, since nothing attested
      // which model produced them.
      let tinfoilUsage = null;
      if (chosen.spec.apiStyle === 'tinfoil') {
        tinfoilUsage = parseUsageMetrics(usageMetricsOf(upRes));
        if (!tinfoilUsage && chosen.statusCode >= 200 && chosen.statusCode < 300) {
          reportEnclaveError(ERROR_CODES.TINFOIL_USAGE_MISSING, {
            request_id: requestId,
            settle_id: settleId,
            terminal: false,
            credit_id: billedCreditId,
            api_key_id: billedApiKeyId,
            model: reportableModel,
            provider: TINFOIL_PROVIDER,
            upstream_status: chosen.statusCode,
            query_source: querySource,
            trace: traceOf(traceRec),
          });
        }
      }
      sendSettle({ usage, usageSource, inputTokens, outputTokens, tinfoilUsage });
    })();
  };
  const sendSettle = ({ usage, usageSource, inputTokens, outputTokens, tinfoilUsage }) => {
    // Content-free billing metadata. For a direct upstream: bill on the public
    // or_slug (so hp margins match) and report provider + wire/served model ids
    // so hp prices from the catalog rate table (no OR cost / generation id).
    reportSettlement({
      request_id: String(requestId),
      settle_id: settleId,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      failure_code: settleFailureCode,
      // Undefined (dropped from the JSON body) unless an upstream status set it.
      failure_status: settleFailureStatus,
      model: chosenDirect ? chosen.spec.orSlug : usage.model || model,
      input_tokens: tinfoilUsage ? tinfoilUsage.promptTokens : inputTokens,
      output_tokens: tinfoilUsage ? tinfoilUsage.completionTokens : outputTokens,
      // 'upstream' when the numbers above came from the usage frame, 'counted'
      // when they are the enclave's own count of delivered output (see
      // settleNow). hp can tell an exact bill from an estimated one.
      usage_source: tinfoilUsage ? 'upstream' : usageSource,
      // The authorize-time estimate input (#171), so hp can compare it with the
      // billed input_tokens per model and tune its family factors.
      input_tokens_o200k: inputMeasure.input_tokens_o200k,
      total_cost_usd: chosenDirect ? 0 : usage.totalCost,
      cost_source: tinfoilUsage ? TINFOIL_COST_SOURCE : chosenDirect ? 'catalog-tokens' : 'stream',
      generation_id: chosenDirect ? '' : usage.generationId,
      query_source: querySource,
      cache_read_tokens: tinfoilUsage ? tinfoilUsage.cachedPromptTokens : usage.cacheReadTokens,
      cache_write_tokens: usage.cacheWriteTokens,
      // Verbatim reasoning count; hp folds it into billed output ONLY for
      // providers whose descriptor marks reasoning additive (Vertex).
      reasoning_tokens: usage.reasoningTokens,
      // Must agree with horse-power's `hasWebSearch`, not just test plugins:
      // Auto mode declares the server tool instead, and Auto is the default for
      // a user who never touched the setting, so the old plugins-only test
      // recorded almost every enclave search as offline (#8).
      is_online: hasWebSearch(basePayload),
      // Searches a direct provider actually RAN, counted from the citations it
      // returned (veniceCitations.mjs) — not the mode that was requested.
      // Venice charges a flat amount per search; hp prices it from this count.
      // Absent for every route that does not bill searches this way.
      web_search_calls: veniceCitations ? veniceCitations.searches : undefined,
      // The web-search fee's two inputs (horse-power #1088; Oct 17-19 security
      // reports, hel's paid-fee finding, Matt's item 9), OpenRouter rows only:
      // a direct provider prices its own searches (web_search_calls above) and
      // the private relay runs none. `is_byok` is which cost regime the usage
      // frame put the row in (the BYOK provider's inference cost excludes the
      // Exa charge; OpenRouter's `cost` includes it), a boolean only once a
      // frame was read; absent means UNKNOWN to hp, never "not BYOK".
      // `web_search_engine` is judged on the OpenRouter body actually sent,
      // after the transforms and strips, not on what the caller asked for.
      is_byok: chosenDirect ? undefined : usage.isByok,
      web_search_engine: chosenDirect ? undefined : webSearchEngineOf(payload),
      is_free_model: isFreeModel,
      // PII redaction: the number of SUCCESSFUL detector calls behind this
      // request (hp bills the redaction per call). Absent when it was off.
      pii_redaction_calls: piiMapping ? piiCalls : undefined,
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
      // Smart routing: hp stamps isAutoclaw/autoModel on the row and keeps
      // the tier for reporting (horse-power #964). Absent otherwise.
      is_autoclaw: Boolean(smartRoute),
      autoclaw_tier: smartRoute ? smartRoute.tier : undefined,
      provider: chosenDirect ? chosen.spec.provider : 'openrouter',
      // Who actually answered behind OpenRouter, as OpenRouter names it on the
      // usage chunk (cost.mjs bounds its shape). Always present so the backend
      // can tell "not reported" from an older enclave; null for a direct or
      // private upstream, which serves the request itself, and when no usage
      // chunk named one. `provider` above keeps its meaning.
      upstream_provider: chosenDirect ? null : usage.provider ?? null,
      upstream_model: chosenDirect ? chosen.spec.upstreamModel : undefined,
      // For Tinfoil ONLY the usage line's model is attested; the body's
      // `model` field is the router's own echo and must not be reported as
      // served, or hp would price a request nothing vouched for.
      // On a translated direct route this is the upstream's FIRST echo, the
      // one the receipt was signed with (receipt.mjs servedModelReport); a
      // terminal event that named a different model travels beside it as
      // `served_model_terminal`, present only when the two disagree.
      served_model: chosen.spec.apiStyle === 'tinfoil' ? tinfoilUsage?.model : servedModelReport(translator, usage.model).servedModel,
      served_model_terminal: chosen.spec.apiStyle === 'tinfoil' ? undefined : servedModelReport(translator, usage.model).terminalModel,
      // #2 (2026-09-10 OR-share audit): the enclave was a blind spot for
      // direct-vs-bail — settle records carried the served `provider` but not
      // WHY a request bailed off the direct seam, so an 88%-OpenRouter share on
      // agentic Claude traffic went unnoticed. Mirror horse-power's meta.route /
      // route_bail_reason / route_bail_field / direct_provider so the same
      // reporting works on both surfaces. The bail reason is the FIRST direct
      // candidate that skipped (eligibility/build), else 'attempt_failed' when a
      // direct upstream was tried and errored; 'none' when a direct candidate
      // actually served. hp persists these via extraMeta.
      route: chosenDirect ? 'direct' : 'openrouter',
      route_bail_reason: chosenDirect
        ? 'none'
        : skippedCandidates[0]?.reason ??
          // Direct failures only: a retried OpenRouter attempt is on the list
          // for the receipt and the trace, but no direct upstream was tried.
          (failedCandidates.some((f) => f.provider !== 'openrouter') ? 'attempt_failed' : undefined),
      // Bounded like the trace's copy of the same value (trace.mjs
      // skippedCandidate → label): the field is a caller-chosen body member
      // name, so it goes through the catalog-identifier shape or not at all
      // (Oct 17-19 security reports: 0xboomzy).
      route_bail_field: chosenDirect ? undefined : routeBailField(skippedCandidates[0]?.field),
      direct_provider: chosenDirect ? chosen.spec.provider : undefined,
      // What happened to the request, for support lookups by credit id
      // (trace.mjs). Bounded and content-free; undefined if it failed to build.
      trace: traceOf(traceRec),
    });
  };

  // The client went away before the stream finished. Cancel the upstream at
  // once: every provider we route to stops generating AND billing when the
  // connection closes (OpenRouter: "immediately stops model processing and
  // billing" for Fireworks, Anthropic, OpenAI, xAI, DeepSeek; Fireworks direct:
  // "close the connection to stop generation and avoid billing for ungenerated
  // tokens"; measured 2026-09-21: 16-18% of a full run billed after a 3 s
  // abort, generation time ending at the abort). The old drain — keep reading
  // for 120 s "because the provider bills the whole generation anyway" — was
  // built on a premise that is false for these providers, so it paid for two
  // minutes of output nobody read and then, having destroyed the socket before
  // the usage frame, billed the customer nothing. The destroy lands in the
  // upstream 'error' handler, which settles from the local output count
  // (settleNow) and, with clientGone set, files no stream_failed report.
  // Outcome and trace say client_abort, first-writer-wins over the later end.
  // The listener itself is registered at the top of the handler; this is the
  // point from which it has an upstream to cancel. Same synchronous block as
  // `src.on('error')` below, so the destroy always has a handler to land in.
  onClientGone = () => {
    reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
      request_id: requestId,
      settle_id: settleId,
      // Not final: the cancelled upstream still settles from what was delivered.
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: chosenProvider,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
  };
  abortableUpRes = upRes;
  // The client left between the upstream's headers and here (the EHBP
  // encryptor and the Class B opener await in between): the close has already
  // been seen and named the outcome; cancel and report now, and the 'error'
  // handler below settles what little was delivered.
  const abortedBeforeWired = clientGone;

  src.on('end', () => {
    // Drain the stages in order: what one still holds goes through every
    // stage after it, then the extractor/rewriter path. The translator and
    // the mirror/citations never share a response (`!translator` gates), so
    // without redaction this is each stage's own tail, as before.
    let tail = translator ? translator.finish() : Buffer.alloc(0);
    // With redaction on the extractor reads the upstream's bytes (see the data
    // handler), so the translator's tail reaches it here, unrestored.
    if (piiRestorer && tail.length > 0) extractor.feed(tail);
    // Whatever the restorer still holds (a whole non-stream body, the last
    // partial event) is restored before the stages below see it.
    if (piiRestorer && !restoreFailed) {
      try {
        tail = Buffer.concat([piiRestorer.push(tail), piiRestorer.finish()]);
        counters.piiRestored(piiRestorer.misses);
      } catch (e) {
        failRestore(e);
      }
    }
    if (restoreFailed) {
      // The client side is already closed; the extractor has already read
      // the whole upstream answer, so this only settles.
      settleNow();
      return;
    }
    if (reasoningMirror) {
      // A non-streaming body is released whole here; a stream's last partial
      // line (never the case for well-formed SSE) likewise.
      tail = Buffer.concat([tail.length > 0 ? reasoningMirror.feed(tail) : tail, reasoningMirror.finish()]);
    }
    if (veniceCitations) {
      // A non-streaming body is released whole here, rewritten; a stream's
      // last partial line (never the case for well-formed SSE) likewise.
      tail = Buffer.concat([tail.length > 0 ? veniceCitations.feed(tail) : tail, veniceCitations.finish()]);
    }
    if (tail.length > 0) {
      if (!piiRestorer) extractor.feed(tail);
      // The terminal event of a translated stream can arrive only here.
      if (capApplied && !capHit && /"finish_reason"\s*:\s*"length"/.test(capTail + tail.toString('utf8'))) {
        capHit = true;
      }
      release(receiptGate.feed(rewriter.feed(tail), extractor.result.model));
    }
    release(receiptGate.feed(rewriter.finish(), extractor.result.model));
    release(receiptGate.finish());
    writeChain.then(() => res.end()).catch(() => { if (!res.writableEnded) res.end(); });
    traceRec.setStreamEnd(capHit ? 'cap_hit' : 'clean');
    settleNow();
  });
  src.on('error', (e) => {
    log(`upstream stream error: ${e.message}`);
    if (clientGone) {
      // The client had already hung up and the res 'close' handler cancelled
      // the upstream: this error is that cancellation (or the upstream dying
      // with nobody reading). Not a failure the user saw, and already counted
      // and traced as client_abort: reporting it as stream_failed doubled
      // every abort into a paged "failure" (#enclave-fallbacks, 2026-09-20:
      // 76 stream_failed, all of them this). Settle from what was delivered.
      if (!res.writableEnded) res.end();
      settleNow();
      return;
    }
    traceRec.setStreamEnd('upstream_error');
    settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
    // The user saw a truncated answer and may already have been billed for the
    // prefill, so this is not merely cosmetic.
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      // Not final: settleNow() below still settles this request.
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: chosenProvider,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    // A stream that died before its first frame still says where it went.
    // Ended through the write chain, as a clean end is: an EHBP write is
    // asynchronous, and ending ahead of it would drop the receipt.
    release(receiptGate.finish());
    const endNow = () => {
      if (!res.writableEnded) res.end();
    };
    writeChain.then(endNow).catch(endNow);
    settleNow();
  });
  if (abortedBeforeWired) {
    abortableUpRes.destroy(new Error('client aborted; upstream cancelled'));
    onClientGone();
  }
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
 * exists, which ACME makes true: a challenge certificate while an order is in
 * flight, the issued certificate once installed (since #195 also the DEFAULT,
 * so an unknown name is served it), the boot self-signed one until then, and
 * long-lived connections that still carry whatever they were served. Binding
 * the attestation to a global meant committing to a certificate the client
 * was NOT served, so a client doing attested-TLS verification would reject a
 * perfectly good connection.
 *
 * Confirmed on the dev enclave 2026-09-03: after the first successful ACME
 * order the attested hash was 0b87e157... while clients were served c4fa8b65...
 * The feature broke the very property it exists to provide.
 *
 * `socket.getCertificate()` returns the LOCAL certificate for this connection,
 * which is exactly the one the peer saw. Falls back to the served DEFAULT when
 * unavailable -- what such a connection was served -- and connectionSigningKey
 * falls back the same way for the same socket, so the two cannot disagree.
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
  if (!servedIdentity) return TLS_PRIVATE_KEY; // before start(): no request can arrive
  // By the SPKI of the certificate this socket was served (#195): the default
  // context follows the issued certificate, so a connection whose SNI has no
  // issued entry (a bare-IP client) is served the issued certificate too, and
  // a lookup by name would sign it with the wrong key.
  return (
    servedIdentity.signingKeyFor(req?.socket?.getCertificate?.()) ||
    // A TLS-ALPN-01 challenge certificate is held by acmeRunner, not by the
    // identity, and is served for its own name only.
    challengeSigningKey(req?.socket?.servername) ||
    // A served certificate nobody here holds the key for: the receipt goes
    // UNSIGNED. Unsigned is honest; signed with another key is the alarm a
    // real attack raises (#112).
    null
  );
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
    // That was exactly the shape here: boot.sh self-signed with RSA-2048 (P-256
    // since #195) while ACME issues a P-256 certificate, so the attested hash matched nothing
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
    log(`attestation: per-connection SPKI unavailable (${e.message}); using the served default`);
  }
  return servedIdentity ? servedIdentity.currentSpki() : { hex: CERT_SPKI_SHA256_HEX, b64: CERT_SPKI_DER_B64 };
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

/**
 * `POST /v1/decisions` (+ `/decisions`, `/v1/systemone`): OpenRouter's
 * structured-decision modality, in-enclave. See decisions.mjs for the
 * contract. Same envelope as a chat request — cleartext auth headers, an
 * optionally HPKE-sealed body, hp authorize before the key is spent, one
 * settle after — but the upstream is a single JSON round-trip to
 * `/api/alpha/decisions`, so none of the chat path's streaming, routing
 * transforms, direct candidates or receipts apply.
 *
 * Every early return names its outcome through `finalize`, exactly as
 * chatCompletion does, so /health's by_outcome invariant holds here too.
 */
async function handleDecisions(req, res) {
  const finalize = counters.beginRequest();
  const ctx = {};
  try {
    await decisionsRequest(req, res, finalize, ctx);
  } catch (e) {
    finalize(ERROR_CODES.INTERNAL_ERROR);
    if (e && typeof e === 'object') {
      e.reportFields = handlerFailureFields(ctx, ctx.traceRec ? traceOf(ctx.traceRec) : undefined);
    }
    throw e;
  }
}

async function decisionsRequest(req, res, finalize, ctx = {}) {
  // Bounded once for every egress (trace.mjs resolveRequestId): the caller's
  // id only in the accepted shape, else one minted here.
  const { requestId } = resolveRequestId(req.headers['x-request-id']);
  const settleId = randomUUID();
  ctx.requestId = requestId;
  ctx.settleId = settleId;

  const traceRec = createTraceRecorder();
  traceRec.setClient({
    requestId: req.headers['x-request-id'],
    userAgent: req.headers['user-agent'],
    clientIp: req.socket?.clientIp,
  });
  ctx.traceRec = traceRec;
  traceRec.setEnclave({
    version: ENCLAVE_VERSION,
    worker: cluster.isWorker ? cluster.worker.id : 0,
    box: ENCLAVE_BOX_ID || undefined,
  });
  // Never a stream: the answer is one JSON body.
  traceRec.setStreaming(false);

  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  if (!creditId && !authHeader) {
    finalize('unauthenticated');
    return sendJson(res, 401, {
      error: { message: 'Missing x-credit-id, Authorization or x-api-key', code: 401 },
    });
  }
  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  let body;
  let ehbpCtx = null;
  try {
    // Bounded before authorize (decisions.mjs): the limit covers the sealed
    // ciphertext, since readRawBody counts the framed wire body.
    const rawBody = await readRawBody(req, DECISIONS_MAX_REQUEST_BODY_BYTES);
    const encapKey = req.headers['ehbp-encapsulated-key'];
    if (encapKey) {
      if (!ehbpRecipient) throw new Error('EHBP not initialised');
      const opened = await ehbpRecipient.openRequest(String(encapKey), rawBody);
      body = JSON.parse(opened.plaintext.toString('utf8'));
      ehbpCtx = { exportedSecret: opened.exportedSecret, requestEnc: opened.requestEnc };
    } else {
      body = JSON.parse(rawBody.toString('utf8'));
    }
  } catch (e) {
    log(`decisions request unreadable: ${e.message}`);
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendJson(res, 400, { error: { message: unreadableBodyMessage(e), code: 400 } });
  }
  traceRec.setEhbp(ehbpCtx !== null);
  if (ehbpCtx !== null) counters.ehbp();

  // Shape only — field names and messages are content-free by construction
  // (the validator never echoes a value). The model is reported to hp, which
  // checks it against the live decisions catalog at /authorize.
  const validation = validateDecisionsRequest(body);
  if (validation.kind === 'invalid') {
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendJson(res, 400, {
      error: {
        message: validation.error.message,
        param: validation.error.field,
        code: 400,
      },
    });
  }
  const request = validation.value;

  // The client went away. Registered before the first await so a disconnect
  // during authorize is seen too. Once the upstream call is in flight it is
  // NOT cancelled (the provider bills the whole answer either way) and it
  // still settles; this only records the outcome, first-writer-wins over the
  // later `clean`, so an abandoned answer is not counted as a delivered one.
  let clientGone = false;
  res.on('close', () => {
    if (res.writableFinished) return;
    clientGone = true;
    traceRec.setStreamEnd('client_abort');
    finalize(ERROR_CODES.CLIENT_ABORT);
  });

  // hp bounds spend on the o200k count of the serialized state+questions and
  // learns `endpoint: 'decisions'` from the same object (it rides the measure
  // into the authorize body). Counts only — never content.
  const inputMeasure = await measureDecisionsInput(request);
  const auth = await authorizeWithHorsepower(
    req.headers,
    request.model,
    undefined,
    inputMeasure.input_bytes,
    inputMeasure,
    req.socket?.clientIp,
    requestId,
    { settleId },
  );
  traceRec.mark('authorized');
  if (!auth.ok) {
    const code =
      auth.failure === 'timeout'
        ? ERROR_CODES.AUTHORIZE_TIMEOUT
        : auth.failure === 'unreachable'
          ? ERROR_CODES.AUTHORIZE_UNREACHABLE
          : ERROR_CODES.AUTHORIZE_REJECTED;
    // A balance backoff (hp #1022) is the system working as designed, at the
    // volume that buried real failures: not reported, only counted.
    if (!auth.backoff) {
      reportEnclaveError(code, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        upstream_status: auth.status,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    finalize(code);
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    }, authRefusalHeaders(auth));
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;
  // From here an unanticipated throw is reported against the billed account.
  ctx.creditId = billedCreditId;
  ctx.apiKeyId = billedApiKeyId;
  ctx.querySource = querySource;
  // The client left while hp was authorizing: nothing has been spent, so
  // nothing is called upstream and nothing settles (the close handler above
  // already recorded the outcome). Reported as terminal so hp releases the
  // balance hold it took at authorize (horse-power #1046); a client abort
  // maps to no Account Activity row.
  if (clientGone) {
    reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    return;
  }
  // hp's resolution wins, as on the chat path: today it echoes the slug it
  // found in its decisions catalog, and if it ever resolves an alias the
  // enclave must serve and settle under the slug hp priced, not the caller's.
  const modelResolvedByHp =
    typeof auth.resolved_model === 'string' && !!auth.resolved_model;
  if (modelResolvedByHp) request.model = auth.resolved_model;
  const model = request.model;
  // Only a slug hp resolved against its catalog is safe to report (see
  // reportableModel in chatCompletion); an older hp leaves it unnamed.
  const reportableModel = modelResolvedByHp ? model : undefined;
  ctx.model = reportableModel;

  // One upstream, one dialect: OpenRouter's alpha decisions endpoint over the
  // same allowlisted tunnel the chat path uses. The request goes as validated
  // — no provider block, no usage.include (the endpoint always states cost).
  traceRec.setRoute({
    chosen: 'openrouter',
    upstreamHost: cfg.orHost,
    apiStyle: 'decisions',
    skipped: [],
    failed: [],
  });
  counters.provider('openrouter');
  const bodyStr = JSON.stringify(request);
  // One deadline spans the headers AND the body read below: destroying the
  // request tears the response down too, so a stalled or trickling upstream
  // surfaces as an error on whichever wait is pending (unreachable before
  // headers, unreadable after) instead of holding the handler open.
  let upstreamReq = null;
  const deadline = setTimeout(() => {
    if (upstreamReq) upstreamReq.destroy(new Error('decisions upstream deadline'));
  }, DECISIONS_UPSTREAM_DEADLINE_MS);
  const attempt = await new Promise((resolve) => {
    upstreamReq = https.request(
      {
        host: '127.0.0.1',
        port: cfg.orPort,
        servername: cfg.orHost,
        method: 'POST',
        path: DECISIONS_UPSTREAM_PATH,
        headers: {
          host: cfg.orHost,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(bodyStr),
          authorization: `Bearer ${UPSTREAM_KEYS.openrouter}`,
          'http-referer': 'https://ppq.ai/',
          'x-title': 'PPQ.AI',
        },
      },
      (upRes) => {
        const code = upRes.statusCode || 0;
        resolve({ ok: code >= 200 && code < 300, statusCode: code, res: upRes });
      },
    );
    upstreamReq.on('error', (e) => resolve({ ok: false, error: e }));
    upstreamReq.write(bodyStr);
    upstreamReq.end();
  });
  if (attempt.error || !attempt.res) {
    clearTimeout(deadline);
    log(`decisions upstream error: ${attempt.error?.message}`);
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
  }

  // Buffer the (small) JSON answer; it is needed whole for the settle and,
  // for an EHBP client, sealed as one chunk.
  let upstreamBody;
  try {
    upstreamBody = await readRawBody(attempt.res, DECISIONS_MAX_RESPONSE_BYTES);
  } catch (e) {
    clearTimeout(deadline);
    log(`decisions upstream body unreadable: ${e.message}`);
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      upstream_status: attempt.statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.STREAM_FAILED);
    if (!res.headersSent)
      sendJson(res, 502, { error: { message: 'upstream response unreadable', code: 502 } });
    return;
  }
  clearTimeout(deadline);
  traceRec.mark('firstByte');
  traceRec.addBytes(upstreamBody.length);
  // Only 2xx is an answer. Anything else (a 3xx included) is passed through
  // with its status, reported, and never settled: nothing was billed for it.
  const served = attempt.ok;
  // A refused answer is OpenRouter's own error body, and it carries what the
  // chat path (sanitizedErrorStream, above) and the dialect relay
  // (sanitizeUpstreamErrorBody) already strip: PayPerQ's OpenRouter org
  // `user_id`, the serving sub-provider, openrouter.ai links and the vendor
  // name. This route was the one of three that wrote it verbatim, so one bad
  // model id on /v1/decisions read the org id the other two routes hide
  // (Oct 17-19 security reports, riskydwi27). Same policy on every route now:
  // the body is sanitized, or replaced by the generic one when it is too large
  // or too nested to sanitize safely — never the raw bytes.
  const wire = served ? { body: upstreamBody, replaced: false } : sanitizedErrorBodyBuffer(upstreamBody, attempt.statusCode);

  // The answer's billing facts (decisions.mjs), read BEFORE it is sent: a 2xx
  // that is not JSON, or carries no usage, is a served answer the enclave
  // cannot price. It still goes out (the caller's answer is not ours to
  // withhold) and still settles — at $0 with the decisions cost_source, which
  // hp records as a visible $0 row — but only this report says it happened.
  let parsed = null;
  if (served) {
    try {
      parsed = JSON.parse(upstreamBody.toString('utf8'));
    } catch {
      parsed = null;
    }
  }
  const usage = served ? decisionsUsage(parsed) : null;
  // A present-but-corrupt cost (negative, NaN, a string) is as unpriced as an
  // absent one: decisionsUsage zeroes it, so without this it would settle as
  // a quiet $0 instead of being reported.
  const reportedCost = parsed?.usage?.cost;
  const usageMissing =
    served &&
    (parsed === null || typeof reportedCost !== 'number' || !Number.isFinite(reportedCost) || reportedCost < 0);

  if (!served) {
    // Passed through verbatim, like the chat path; still reported so a
    // provider 400ing every request is visible. Nothing to settle: the
    // endpoint bills nothing for a refused request.
    reportEnclaveError(ERROR_CODES.UPSTREAM_ERROR_STATUS, {
      request_id: requestId,
      settle_id: settleId,
      // Final: a refused decisions request never settles.
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      upstream_status: attempt.statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_ERROR_STATUS);
  } else if (usageMissing) {
    reportEnclaveError(ERROR_CODES.DECISIONS_USAGE_MISSING, {
      request_id: requestId,
      settle_id: settleId,
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      upstream_status: attempt.statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.DECISIONS_USAGE_MISSING);
  } else if (!clientGone) {
    finalize('clean');
  }

  // Seal the whole body BEFORE writeHead so a sealing failure can still be
  // answered with a status — and never skips the settle below: the upstream
  // has answered and billed whether or not the client could be told.
  const respHeaders = {
    // The generic body is JSON whatever the upstream's error page was.
    'content-type': wire.replaced ? 'application/json' : attempt.res.headers['content-type'] || 'application/json',
  };
  // Set only when the answer could not be sealed back: it is still billed.
  let settleFailureCode;
  try {
    let outBody = wire.body;
    if (ehbpCtx) {
      const respEnc = await ehbpRecipient.responseEncryptor(ehbpCtx.exportedSecret, ehbpCtx.requestEnc);
      respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
      outBody = await respEnc.encrypt(wire.body);
    }
    res.writeHead(attempt.statusCode, respHeaders);
    res.end(outBody);
  } catch (e) {
    log(`decisions response sealing failed: ${e.message}`);
    settleFailureCode = RESPONSE_SEAL_FAILED;
    if (!res.headersSent) sendJson(res, 502, { error: { message: 'response sealing failed', code: 502 } });
    else if (!res.writableEnded) res.end();
  }
  traceRec.mark('end');
  if (!clientGone) traceRec.setStreamEnd(served ? 'clean' : 'upstream_error');

  if (!served) return;

  // Settle from the answer's own usage block: usage.cost is OpenRouter's
  // inline invoice for the call (zeros when the answer carried none — see
  // usageMissing above).
  ctx.settleStarted = true;
  reportSettlement({
    request_id: String(requestId),
    settle_id: settleId,
    credit_id: billedCreditId,
    api_key_id: billedApiKeyId,
    failure_code: settleFailureCode,
    // The slug hp authorized (its catalog + margin key), not the dated
    // permaslug the answer names — that travels as served_model.
    model,
    endpoint: inputMeasure.endpoint,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    input_tokens_o200k: inputMeasure.input_tokens_o200k,
    total_cost_usd: usage.totalCost,
    cost_source: DECISIONS_COST_SOURCE,
    generation_id: usage.generationId,
    query_source: querySource,
    is_online: false,
    is_free_model: false,
    auto_model: false,
    provider: 'openrouter',
    served_model: usage.servedModel,
    route: 'openrouter',
    trace: traceOf(traceRec),
  });
}

/**
 * `POST /v1/messages`: the Anthropic Messages dialect, in-enclave (#275).
 *
 * horse-power serves this route on the enclave-bypass host by forwarding the
 * body as-is to OpenRouter's `/api/v1/messages`; this does the same from
 * inside the enclave. Same envelope as a chat request — cleartext auth
 * headers, an optionally HPKE-sealed body, hp authorize before the key is
 * spent, one settle after — but the frames go through VERBATIM: no routing
 * transforms, no direct candidates, no rebranding, no receipt. Only the
 * numbers are read (messages.mjs), for the settle.
 *
 * Every early return names its outcome through `finalize`, exactly as
 * chatCompletion does, so /health's by_outcome invariant holds here too.
 */
async function handleMessages(req, res) {
  return handleDialectRelay(req, res, MESSAGES_DIALECT);
}

/**
 * One handler for every dialect the enclave relays verbatim (#275, #280):
 * the Anthropic Messages API and the OpenAI Responses API. The dialect
 * object (messages.mjs, responses.mjs) holds the pure parts — validation,
 * the input measure, the usage extractor and delta counter, the error
 * shapes, the cap and identity fields — and this file holds what needs the
 * tunnels, EHBP, hp and the settle queue.
 *
 * Every early return names its outcome through `finalize`, exactly as
 * chatCompletion does, so /health's by_outcome invariant holds here too.
 */
async function handleDialectRelay(req, res, d) {
  const finalize = counters.beginRequest();
  const ctx = {};
  try {
    await relayDialectRequest(req, res, finalize, ctx, d);
  } catch (e) {
    finalize(ERROR_CODES.INTERNAL_ERROR);
    if (e && typeof e === 'object') {
      e.reportFields = handlerFailureFields(ctx, ctx.traceRec ? traceOf(ctx.traceRec) : undefined);
    }
    throw e;
  }
}

/**
 * An error in the dialect the caller speaks; never content, never an upstream's
 * own text. `code`, when given, is set on the envelope's `error.code`.
 */
function sendDialectError(res, d, status, message, extraHeaders = {}, code = undefined) {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }
  const envelope = d.errorBody(status, message);
  if (code) envelope.error.code = code;
  const body = JSON.stringify(envelope);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

/**
 * A `pii_redaction` refusal in the caller's own error envelope (Anthropic for
 * Messages, OpenAI for Responses), carrying the stable PII code so a client can
 * tell it from any other 400/503.
 */
function sendPiiDialectError(res, d, status, code) {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }
  const envelope = d.errorBody(status, piiErrorMessage(code));
  envelope.error.code = code;
  const body = JSON.stringify(envelope);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

/** The PII adapter (pii/dialects) for each relayed dialect, by dialect name. */
const PII_RELAY_DIALECTS = Object.freeze({ messages: piiMessagesDialect, responses: piiResponsesDialect });

/**
 * The hp refusal codes a dialect envelope keeps. An exact allow-list: hp's
 * other codes are internal, and the dialect restates only the message.
 */
const RELAYED_AUTH_CODES = new Set([PII_ERRORS.INSUFFICIENT_BALANCE]);

function relayedAuthCodeOf(body) {
  const c = body?.error?.code;
  return typeof c === 'string' && RELAYED_AUTH_CODES.has(c) ? c : undefined;
}

/** hp's refusal (chat-shaped `{error:{message}}` or `{error:'…'}`), restated for the dialect. */
function dialectMessageOf(body, fallback) {
  const m = body?.error?.message ?? body?.message ?? body?.error;
  return typeof m === 'string' && m ? m : fallback;
}

async function relayDialectRequest(req, res, finalize, ctx, d) {
  // Bounded once for every egress (trace.mjs resolveRequestId): the caller's
  // id only in the accepted shape, else one minted here.
  const { requestId } = resolveRequestId(req.headers['x-request-id']);
  const settleId = randomUUID();
  ctx.requestId = requestId;
  ctx.settleId = settleId;

  const traceRec = createTraceRecorder();
  traceRec.setClient({
    requestId: req.headers['x-request-id'],
    userAgent: req.headers['user-agent'],
    clientIp: req.socket?.clientIp,
  });
  ctx.traceRec = traceRec;
  traceRec.setEnclave({
    version: ENCLAVE_VERSION,
    worker: cluster.isWorker ? cluster.worker.id : 0,
    box: ENCLAVE_BOX_ID || undefined,
  });

  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  if (!creditId && !authHeader) {
    finalize('unauthenticated');
    return sendDialectError(
      res,
      d,
      401,
      'Missing credentials. Send a PPQ API key as `x-api-key: <key>` or `Authorization: Bearer <key>`.',
    );
  }
  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  let body;
  let ehbpCtx = null;
  try {
    const rawBody = await readRawBody(req, d.maxRequestBodyBytes);
    const encapKey = req.headers['ehbp-encapsulated-key'];
    if (encapKey) {
      if (!ehbpRecipient) throw new Error('EHBP not initialised');
      const opened = await ehbpRecipient.openRequest(String(encapKey), rawBody);
      body = JSON.parse(opened.plaintext.toString('utf8'));
      ehbpCtx = { exportedSecret: opened.exportedSecret, requestEnc: opened.requestEnc };
    } else {
      body = JSON.parse(rawBody.toString('utf8'));
    }
  } catch (e) {
    log(`${d.name} request unreadable: ${e.message}`);
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendDialectError(res, d, 400, unreadableBodyMessage(e));
  }
  traceRec.setEhbp(ehbpCtx !== null);
  if (ehbpCtx !== null) counters.ehbp();

  // Shape only, and only what this handler itself reads; the validator never
  // echoes a value, so field names and messages are content-free.
  const validation = d.validate(body);
  if (validation.kind === 'invalid') {
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    // The message already names the field (messages.mjs); the field rides
    // alone when it does not.
    const { field, message } = validation.error;
    return sendDialectError(res, d, 400, message.startsWith(`${field}:`) ? message : `${field}: ${message}`);
  }
  const { stream } = validation.value;
  traceRec.setStreaming(stream);

  // `pii_redaction`, by value (pii/pipeline.mjs), as on the chat path: removed
  // here whenever it is present, so OpenRouter never sees it; `false` means no
  // redaction, `true` redacts below (after authorize), anything else is a 400.
  // Every refusal that can be decided from the body alone comes before
  // authorize, so it takes no balance hold.
  const piiFlag = takePiiFlag(body);
  if (piiFlag === 'invalid') {
    finalize(PII_ERRORS.INVALID);
    return sendPiiDialectError(res, d, 400, PII_ERRORS.INVALID);
  }
  const piiDialect = piiFlag === 'on' ? PII_RELAY_DIALECTS[d.name] : null;
  if (piiFlag === 'on' && !piiDialect) {
    finalize(PII_ERRORS.UNSUPPORTED_ENDPOINT);
    return sendPiiDialectError(res, d, 400, PII_ERRORS.UNSUPPORTED_ENDPOINT);
  }
  if (piiDialect && isPrivateModel(body.model)) {
    finalize(PII_ERRORS.UNSUPPORTED_MODEL);
    return sendPiiDialectError(res, d, 400, PII_ERRORS.UNSUPPORTED_MODEL);
  }
  // Each request gets a fresh mapping numbered from _1, and a turn the
  // upstream stored for us was either sent in the clear or written with a
  // mapping that is gone: a placeholder in it would restore to whoever holds
  // that number now, a different person.
  if (piiDialect === piiResponsesDialect && (body.previous_response_id != null || body.conversation != null)) {
    finalize(PII_ERRORS.UNSUPPORTED_STATE);
    return sendPiiDialectError(res, d, 400, PII_ERRORS.UNSUPPORTED_STATE);
  }

  // The client went away. Registered before the first await so a disconnect
  // during authorize is seen too; `settled` below makes it a no-op once the
  // answer has been accounted for.
  let clientGone = false;
  let settled = false;
  let upRes = null;
  // Set once the answer failed in-band (failAnswer, below): a redacted answer
  // that could not be restored, or a line past the pump's cap. The enclave cut
  // the client off itself, so the close that follows is not a client abort.
  let restoreFailed = false;
  res.on('close', () => {
    if (settled || res.writableFinished || restoreFailed) return;
    clientGone = true;
    traceRec.setStreamEnd('client_abort');
    finalize(ERROR_CODES.CLIENT_ABORT);
    if (upRes) upRes.destroy(new Error('client aborted; upstream cancelled'));
  });

  // hp bounds spend on the o200k count of the dialect body projected onto
  // the chat shape, and learns the endpoint from the same object.
  // Counts only — never content.
  const inputMeasure = await d.measure(body);
  const auth = await authorizeWithHorsepower(
    req.headers,
    body.model,
    d.requestedMaxTokens(body),
    inputMeasure.input_bytes,
    inputMeasure,
    req.socket?.clientIp,
    requestId,
    { settleId, piiRedaction: piiDialect != null },
  );
  traceRec.mark('authorized');
  if (!auth.ok) {
    const code =
      auth.failure === 'timeout'
        ? ERROR_CODES.AUTHORIZE_TIMEOUT
        : auth.failure === 'unreachable'
          ? ERROR_CODES.AUTHORIZE_UNREACHABLE
          : ERROR_CODES.AUTHORIZE_REJECTED;
    // A balance backoff (hp #1022) is the system working as designed, at the
    // volume that buried real failures: not reported, only counted.
    if (!auth.backoff) {
      reportEnclaveError(code, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        upstream_status: auth.status,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    finalize(code);
    const status = auth.status || 402;
    return sendDialectError(
      res,
      d,
      status,
      dialectMessageOf(auth.body, 'not authorized'),
      authRefusalHeaders(auth),
      relayedAuthCodeOf(auth.body),
    );
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;
  ctx.creditId = billedCreditId;
  ctx.apiKeyId = billedApiKeyId;
  ctx.querySource = querySource;
  // Both exits below end a request hp has authorized — and holds a balance
  // reservation for (horse-power #1046) — with no settle to follow, so each
  // is reported as terminal and hp releases the hold. The abort maps to no
  // Account Activity row; the rejection is a 400 the caller saw.
  if (clientGone) {
    reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    return;
  }

  // One upstream, one dialect. The routing directives hp may answer with are
  // decisions for the chat path (the router picks among chat models, smart
  // routing classifies a chat prompt); a Messages body is not projected
  // through either, so a model that needs one is refused here rather than
  // served under a decision nothing made.
  if (auth.auto_router || auth.autoclaw) {
    reportEnclaveError(ERROR_CODES.MODEL_REJECTED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      upstream_status: 400,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.MODEL_REJECTED);
    return sendDialectError(
      res,
      d,
      400,
      `model: ${body.model} is a routing model and is not served on ${d.path}; name a model.`,
    );
  }
  // A private/* model has exactly one place to go, Tinfoil's router (#210),
  // and this relay has exactly one upstream, OpenRouter — so a private prompt
  // must never leave here. horse-power refuses the pairing at
  // /enclave/authorize (a Tinfoil-served id on a dialect endpoint, or an
  // unknown private id, is a 400 there); this is the enclave's own rule for an
  // older or lying hp, the twin of refusesUnroutedPrivate on the chat path.
  // Judged on BOTH the caller's id and hp's resolution, case-folded (Oct 17-19
  // security reports: Raju Arling Toni's /v1/messages finding, zeanxbt's
  // case inversion), before anything about the body is acted on.
  if (isPrivateModel(body.model) || isPrivateModel(auth.resolved_model)) {
    reportEnclaveError(ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      upstream_status: 400,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.MODEL_REJECTED_PRIVATE_PATH);
    // A redacted request keeps its own error contract (the caller's id was
    // already refused before authorize; this is hp resolving onto private/*).
    if (piiDialect) return sendPiiDialectError(res, d, 400, PII_ERRORS.UNSUPPORTED_MODEL);
    return sendDialectError(
      res,
      d,
      400,
      `model: ${body.model} is a private/* model and is not served on ${d.path}; use /v1/chat/completions.`,
    );
  }
  const modelResolvedByHp = typeof auth.resolved_model === 'string' && !!auth.resolved_model;
  if (modelResolvedByHp) body.model = auth.resolved_model;
  const model = body.model;
  const reportableModel = modelResolvedByHp ? model : undefined;
  ctx.model = reportableModel;
  const isFreeModel = auth.is_free === true;

  // Fail closed on the free aliases, as chatCompletion does: a free alias that
  // arrives without hp's is_free directive would otherwise be served on the
  // paid path with whatever paid tools the caller attached. Oct 17-19
  // security reports (martan, hel, Raju Arling Toni): this relay had none of
  // the chat path's free-model guards.
  if (refusesUnauthorizedFree(model, auth.is_free)) {
    reportEnclaveError(ERROR_CODES.FREE_MODEL_UNAUTHORIZED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.FREE_MODEL_UNAUTHORIZED);
    return sendDialectError(res, d, 400, 'free model unavailable on this path');
  }

  // PII redaction, after authorize (a caller who cannot pay costs no detector
  // call), hp's model resolution and the private/* and free-alias refusals
  // above, and before the cap, identity, web search
  // and provider pin, none of which add user text. Fail closed: a detector
  // that errors, times out or is not configured means NOTHING goes upstream
  // and nothing settles; the terminal report releases the hold (horse-power #1046).
  let piiMapping = null;
  let piiCalls = 0;
  if (piiDialect) {
    let redacted = null;
    let failure = { reason: 'not_configured' };
    if (piiDetector) {
      const t0 = Date.now();
      try {
        redacted = await redactBody(piiDialect, body, piiDetector);
        counters.piiRedacted({ calls: redacted.calls, texts: redacted.texts, entities: redacted.entities, latencyMs: Date.now() - t0 });
      } catch (e) {
        failure = e;
      }
    }
    if (!redacted) {
      // The reason token only (TIMEOUT, HTTP_STATUS, ...): never text or spans.
      const reason = piiFailureReason(failure);
      log(`${d.name} pii detector failed: ${reason}`);
      counters.piiFailure(reason);
      reportEnclaveError(ERROR_CODES.PII_DETECTOR_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        query_source: querySource,
        reason,
        trace: traceOf(traceRec),
      });
      finalize(PII_ERRORS.UNAVAILABLE);
      return sendPiiDialectError(res, d, 503, PII_ERRORS.UNAVAILABLE);
    }
    body = redacted.body;
    piiMapping = redacted.mapping;
    piiCalls = redacted.calls;
    // Detection takes a while; a caller who left during it must not start a
    // paid generation. The close listener has already finalized.
    if (clientGone) {
      counters.piiUnbilled(piiCalls);
      reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        query_source: querySource,
        pii_redaction_calls: piiCalls,
        trace: traceOf(traceRec),
      });
      return;
    }
  }
  // Detector calls spent on a request that ends below with no settle: not
  // billed (developer decision), counted and reported so the cost is visible.
  const piiUnbilledCalls = () => {
    if (!piiMapping) return undefined;
    counters.piiUnbilled(piiCalls);
    return piiCalls;
  };

  // The output cap (#987) lands on the dialect's own output field.
  if (auth.max_tokens_cap) {
    traceRec.setMaxTokensCap({ applied: true, cap: auth.max_tokens_cap });
    d.applyCap(body, auth.max_tokens_cap);
  }
  // Per-end-user identity on OpenAI-bound requests (issue #657), in the
  // dialect's own field; a no-op for a dialect without one.
  d.applyIdentity(body, billedCreditId, cfg.safetySecret);
  // `:online` (hp #1055), in the transport the dialect's upstream runs. Never
  // on a free model: the search is a paid plugin on a $0 settle (the strip
  // below would remove it again, but injecting it first is wrong twice).
  if (auth.web_search && !isFreeModel) d.applyWebSearch(body);
  // hp's strips, in the dialect's own shape — the chat path has applied both
  // since issue #6 (applyFreeModelStrip / applyToolStrip on the OpenRouter
  // body); this relay forwarded tools and plugins verbatim, so a free
  // credential ran paid web searches that PPQ paid for and the settle
  // recorded as is_free_model. Same order as the chat path: free strip, then
  // the tool-support strip.
  if (isFreeModel) d.applyFreeModelStrip(body);
  if (auth.strip_tools) d.applyToolStrip(body);
  // hp #1060: a hard provider pin (Gemini → google-vertex only) rides these
  // verbatim dialects too; the caller's zdr is kept on top.
  applyHardProviderPin(body, auth.provider_directive);

  traceRec.setRoute({
    chosen: 'openrouter',
    upstreamHost: cfg.orHost,
    apiStyle: d.name,
    skipped: [],
    failed: [],
  });
  counters.provider('openrouter');
  const bodyStr = JSON.stringify(body);
  const upstreamHeaders = {
    host: cfg.orHost,
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(bodyStr),
    authorization: `Bearer ${UPSTREAM_KEYS.openrouter}`,
    'http-referer': 'https://ppq.ai/',
    'x-title': 'PPQ.AI',
  };
  // A redacted answer is restored as text: it must not come back compressed.
  if (piiMapping) upstreamHeaders['accept-encoding'] = 'identity';
  // The dialect's own version/beta headers ride through: they select API
  // behaviour, not identity, and OpenRouter forwards them to the provider.
  for (const h of d.forwardHeaders) {
    if (typeof req.headers[h] === 'string') upstreamHeaders[h] = req.headers[h];
  }
  traceRec.mark('upstreamSent');
  const attempt = await attemptUpstream(
    {
      host: '127.0.0.1',
      port: cfg.orPort,
      servername: cfg.orHost,
      method: 'POST',
      path: d.upstreamPath,
      headers: upstreamHeaders,
    },
    bodyStr,
  );
  if (attempt.error || !attempt.res) {
    log(`${d.name} upstream error: ${attempt.error?.message}`);
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      query_source: querySource,
      pii_redaction_calls: piiUnbilledCalls(),
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendDialectError(res, d, 502, 'upstream unreachable');
  }
  upRes = attempt.res;
  traceRec.mark('upstreamHeaders');
  const served = attempt.ok;

  // Not an answer: passed through with the upstream's status, its body
  // sanitized of the upstream's identity, reported, never settled (the
  // endpoint bills nothing for a refused request).
  if (!served) {
    reportEnclaveError(ERROR_CODES.UPSTREAM_ERROR_STATUS, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      upstream_status: attempt.statusCode,
      query_source: querySource,
      pii_redaction_calls: piiUnbilledCalls(),
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_ERROR_STATUS);
    traceRec.setStreamEnd('upstream_error');
    let errBody;
    try {
      errBody = await readRawBody(upRes, MAX_ERROR_BODY_BYTES);
    } catch {
      errBody = null;
    }
    const text = errBody ? sanitizeUpstreamErrorBody(errBody.toString('utf8')) : null;
    const out = text ?? JSON.stringify(d.errorBody(attempt.statusCode, 'upstream error'));
    if (clientGone) return;
    settled = true;
    try {
      const respHeaders = { 'content-type': upRes.headers['content-type'] || 'application/json' };
      let outBody = Buffer.from(out, 'utf8');
      if (ehbpCtx) {
        const respEnc = await ehbpRecipient.responseEncryptor(ehbpCtx.exportedSecret, ehbpCtx.requestEnc);
        respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
        outBody = await respEnc.encrypt(outBody);
      }
      res.writeHead(attempt.statusCode, respHeaders);
      res.end(outBody);
    } catch (e) {
      log(`${d.name} error sealing failed: ${e.message}`);
      sendDialectError(res, d, 502, 'response sealing failed');
    }
    return;
  }

  // Served. The frames go out verbatim (sealed for an EHBP client, writes
  // serialised to keep chunk order); the extractor and the counter read the
  // same lines for the settle.
  const extractor = new d.UsageExtractor();
  const outputCounter = new d.OutputCounter();
  let respEnc = null;
  let writeChain = Promise.resolve();
  // The last two bytes relayed to the client: an in-band error frame appended
  // while a `data:` line is still open would be swallowed into that line, so
  // failAnswer closes the frame first when these are not already a blank
  // line (CodeRabbit on the GHSA-33j5-hgc8-9mgg F-03 fix).
  let clientTail = Buffer.from('\n\n');
  const atFrameBoundary = () => clientTail[0] === 0x0a && clientTail[1] === 0x0a;
  const writeOut = (buf) => {
    if (!buf || buf.length === 0 || clientGone || restoreFailed) return;
    traceRec.addBytes(buf.length);
    clientTail = buf.length >= 2 ? buf.subarray(-2) : Buffer.concat([clientTail, buf]).subarray(-2);
    if (respEnc) {
      writeChain = writeChain.then(async () => res.write(await respEnc.encrypt(buf)));
    } else {
      res.write(buf);
    }
  };
  // Line pump: the extractor and counter take whole `data:` lines; a line can
  // straddle chunks. On a JSON (non-stream) answer the body is one "line".
  //
  // Oct 17-19 security reports (andzis, GHSA-33j5-hgc8-9mgg F-03): the pump
  // held a line until its newline with no bound, so a data line that never
  // ended grew the worker's heap until the cgroup killed it. Bounded like
  // the relay's own usage buffer (d.maxResponseBytes: no single event is
  // larger than the whole JSON answer the relay would read). A line past the
  // cap fails the answer in-band, the way a restorer that cannot go on does
  // (failAnswer below), and is never fed truncated: the counters would then
  // see a frame the client did not get. Only that line is skipped: the
  // upstream is drained through this same pump, so the lines after it (the
  // terminal frame with the usage block, when it arrives) still reach the
  // extractor and the stream_failed settle bills from real usage, as after a
  // failed restore. During a drain (no client to tell) the line is dropped
  // without a frame. Measured in UTF-8 bytes, the unit of the cap: the bytes
  // of a partial line are summed as the chunks arrive, so a line is never
  // re-scanned. The chat path's counter has its own cap (cost.mjs
  // MAX_LINE_CHARS).
  const decoder = new TextDecoder();
  const maxLineBytes = d.maxResponseBytes;
  let lineBuf = '';
  let lineBufBytes = 0;
  let skippingLine = false;
  let lineCapHit = false;
  let onLineOverflow = null;
  let firstTokenSeen = false;
  const overCap = () => {
    if (lineCapHit) return;
    lineCapHit = true;
    if (onLineOverflow) onLineOverflow();
  };
  const feedLines = (text, rawBytes, last = false) => {
    if (skippingLine) {
      // The rest of the oversized line, up to its newline, is not buffered.
      const nl = text.indexOf('\n');
      if (nl === -1) return;
      skippingLine = false;
      text = text.slice(nl + 1);
      rawBytes = Buffer.byteLength(text, 'utf8');
    }
    lineBuf += text;
    const lines = lineBuf.split('\n');
    lineBuf = last ? '' : lines.pop() || '';
    // No newline in this chunk (nothing to pop but the open line itself):
    // every byte of the chunk joined that line. With one, the remainder is
    // at most this chunk, cheap to measure exactly.
    if (lines.length === 0) lineBufBytes += rawBytes;
    else lineBufBytes = last ? 0 : Buffer.byteLength(lineBuf, 'utf8');
    if (lineBufBytes > maxLineBytes) {
      skippingLine = true;
      lineBuf = '';
      lineBufBytes = 0;
      overCap();
    }
    if (last && lines.length === 1 && lines[0] === '') return;
    for (const line of lines) {
      // A whole line over the cap (chars are a lower bound on bytes, so the
      // exact measure runs only on a line long enough to possibly be over).
      if (line.length > maxLineBytes / 4 && Buffer.byteLength(line, 'utf8') > maxLineBytes) {
        overCap();
        continue;
      }
      extractor.feed(line);
      outputCounter.feed(line);
      // The first generated token, by the one definition every path shares
      // (firstToken.mjs knows all three grammars); never a dialect's own test.
      if (!firstTokenSeen) {
        const kind = detectFirstTokenKind(line);
        if (kind) {
          firstTokenSeen = true;
          traceRec.markFirstToken(kind);
        }
      }
    }
  };
  // A JSON (non-stream) answer is kept whole for its usage block; declared
  // here, ahead of settleNow, which reads it on every path.
  let jsonBody = stream ? null : [];
  let jsonBytes = 0;
  let settleFailureCode;
  let settleFailureStatus;
  // One reader for both the live path and the drain: a stream is fed line
  // by line to the extractor and the counter; a JSON answer is kept whole
  // (bounded) for its usage block. The drain must read a JSON body too, or a
  // sealing failure on a non-streaming answer would settle at zero
  // (CodeRabbit on #276).
  const readUpstream = (raw) => {
    if (stream) {
      feedLines(decoder.decode(raw, { stream: true }), raw.length);
    } else {
      // The byte tally runs past the cap: once the body is too large to keep
      // it is the only measure of the answer left, and the settle below
      // prices from it. Before the Oct 17-19 security reports (daff h) the
      // tally stopped with the buffer, the counter never saw a JSON body
      // (the line pump is stream-only), and an oversized answer went out
      // whole and settled at output 0.
      jsonBytes += raw.length;
      if (jsonBody) {
        if (jsonBytes <= d.maxResponseBytes) jsonBody.push(raw);
        else jsonBody = null; // too large to keep; settles from the byte tally
      }
    }
  };
  async function drainForSettle() {
    await new Promise((resolve) => {
      upRes.on('data', readUpstream);
      upRes.on('end', resolve);
      upRes.on('error', resolve);
    });
    if (stream) feedLines(decoder.decode(), 0, true);
    settleNow();
  }
  const settleNow = () => {
    ctx.settleStarted = true;
    if (settled && ctx.settleSent) return;
    settled = true;
    ctx.settleSent = true;
    traceRec.mark('end');
    counters.streamClosed();
    finalize(traceRec.streamEnd());
    // A JSON answer: its usage block is the authority, read once whole.
    let usage = extractor.result;
    if (!stream && jsonBody) {
      try {
        usage = d.usageOf(JSON.parse(Buffer.concat(jsonBody).toString('utf8')));
      } catch {
        /* not JSON: settle from the stream-shaped parse (likely empty) */
      }
    }
    void (async () => {
      let usageSource = 'upstream';
      let inputTokens = usage.inputTokens;
      let outputTokens = usage.outputTokens;
      if (!(outputTokens > 0)) {
        const counted = await outputCounter.finish().catch(() => ({ chars: 0, tokens: 0 }));
        if (counted.tokens > 0) {
          usageSource = 'counted';
          outputTokens = counted.tokens;
        } else if (!stream && jsonBody === null && jsonBytes > 0) {
          // A JSON answer too large to keep (over d.maxResponseBytes): its
          // usage block was never read and the counter counts stream deltas
          // only, so nothing above priced it, while every byte went to the
          // client. Oct 17-19 security reports (daff h): such an answer
          // settled at output 0 on both dialects, sealed or not. Price it
          // from the bytes the upstream sent at the counter's own overflow
          // ratio (outputCount.mjs: past its cap it estimates by the same
          // chars-per-token figure). The JSON envelope is a rounding error
          // against a multi-megabyte body, and `usage_source: 'counted'`
          // tells hp this is an estimate; the usage-missing report below
          // still fires, so the row is not a quiet one.
          usageSource = 'counted';
          outputTokens = Math.ceil(jsonBytes / OVERFLOW_CHARS_PER_TOKEN);
        }
      }
      // The prompt was consumed when the upstream accepted the request (this
      // block runs only for a served 2xx; a refused status returned above).
      // Same shape, and the same Oct 17-19 fix, as the chat path's settleNow:
      // the input fallback used to sit inside the `counted.tokens > 0` branch,
      // so an abort or a stream death before the first delta settled input 0.
      if (!(inputTokens > 0) && inputMeasure.input_tokens_o200k > 0) {
        usageSource = 'counted';
        inputTokens = inputMeasure.input_tokens_o200k;
      }
      // A served answer the upstream did not price: still settled (from the
      // counts), reported so it is not a quiet $0 row.
      if (!usage.costReported && !clientGone && traceRec.streamEnd() !== 'upstream_error') {
        reportEnclaveError(d.usageMissingCode, {
          request_id: requestId,
          settle_id: settleId,
          terminal: false,
          credit_id: billedCreditId,
          api_key_id: billedApiKeyId,
          model: reportableModel,
          provider: 'openrouter',
          upstream_status: attempt.statusCode,
          query_source: querySource,
          trace: traceOf(traceRec),
        });
      }
      reportSettlement({
        request_id: String(requestId),
        settle_id: settleId,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        failure_code: settleFailureCode,
        failure_status: settleFailureStatus,
        model,
        endpoint: inputMeasure.endpoint,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        usage_source: usageSource,
        input_tokens_o200k: inputMeasure.input_tokens_o200k,
        total_cost_usd: usage.totalCost,
        cost_source: d.costSource,
        generation_id: usage.generationId,
        query_source: querySource,
        cache_read_tokens: usage.cacheReadTokens,
        cache_write_tokens: usage.cacheWriteTokens,
        // Verbatim reasoning count where the dialect reports one (Responses:
        // output_tokens_details); hp folds it in only where it is additive.
        reasoning_tokens: usage.reasoningTokens,
        is_online: d.hasWebSearch(body),
        // The web-search fee's inputs (horse-power #1088), judged on the body
        // this relay actually sent (after the `:online` injection and the
        // strips) and on the usage the dialect reported; see the chat settle.
        is_byok: usage.isByok,
        web_search_engine: webSearchEngineOf(body, d.hasWebSearch),
        is_free_model: isFreeModel,
        auto_model: false,
        provider: 'openrouter',
        // Detector calls this request made, billed by hp at n × fee.
        // In the one payload every settle path builds, so each bills once.
        pii_redaction_calls: piiMapping ? piiCalls : undefined,
        // OpenRouter's serving sub-provider, when the dialect reports one
        // (Messages does; Responses does not without a body-changing opt-in).
        upstream_provider: usage.provider ?? null,
        served_model: usage.servedModel,
        route: 'openrouter',
        trace: traceOf(traceRec),
      });
    })();
  };

  // Sealing comes AFTER every helper the settle needs is defined: a sealing
  // failure drains the upstream through the same pump and settles the same
  // way, and a listener that ran before those bindings existed would throw
  // inside the emitter and take the worker down (CodeRabbit on #276).
  if (ehbpCtx) {
    try {
      respEnc = await ehbpRecipient.responseEncryptor(ehbpCtx.exportedSecret, ehbpCtx.requestEnc);
    } catch (e) {
      log(`${d.name} response sealing failed: ${e.message}`);
      // Billed either way: the upstream is generating. Settle from whatever
      // the stream reports; the client is told only that the answer was lost.
      finalize(ERROR_CODES.STREAM_FAILED);
      sendDialectError(res, d, 502, 'response sealing failed');
      settled = true;
      await drainForSettle();
      return;
    }
  }
  const contentType = upRes.headers['content-type'] || (stream ? 'text/event-stream' : 'application/json');
  const respHeaders = {
    'content-type': contentType,
    'cache-control': 'no-cache',
  };
  if (respEnc) respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
  res.writeHead(attempt.statusCode, respHeaders);
  counters.streamOpened();

  // A redacted answer goes back restored: the extractor and the counter keep
  // reading the placeholder frames (counts only), the client gets the
  // originals. Chosen from the same content type the client is told, and
  // bounded like the relay's own usage buffer.
  const piiRestorer = piiMapping
    ? createResponseRestorer(piiDialect, piiMapping, contentType, { maxBytes: d.maxResponseBytes })
    : null;
  // An answer that cannot go on (a restorer that failed, a line past the
  // pump's cap) ends as failed: in-band on a stream, a cut connection on
  // JSON (its 200 is already out). The upstream is still drained and
  // settled; only the client side stops.
  const failAnswer = (reason) => {
    log(`${d.name} ${reason}`);
    settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
    traceRec.setStreamEnd('upstream_error');
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      upstream_status: attempt.statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    if (stream) {
      // A line past the cap was relayed up to the cap, so the client's stream
      // may be inside a `data:` line: end that frame first or the error event
      // is swallowed into it (an empty frame dispatches nothing in SSE).
      if (!atFrameBoundary()) writeOut(Buffer.from('\n\n', 'utf8'));
      writeOut(Buffer.from(d.streamErrorFrame(), 'utf8'));
      restoreFailed = true;
      writeChain.then(() => res.end()).catch(() => res.destroy());
    } else {
      restoreFailed = true;
      res.destroy();
    }
  };
  const failRestore = (e) => failAnswer(`pii restore failed: ${e?.name || 'error'}`);
  // GHSA-33j5-hgc8-9mgg F-03 (see feedLines): set only now that there is a
  // client to tell and every helper the settle needs is bound.
  onLineOverflow = () => failAnswer(`sse line over ${maxLineBytes} bytes; answer failed`);
  const restore = (raw) => {
    if (!piiRestorer) return raw;
    if (restoreFailed) return null;
    try {
      return piiRestorer.push(raw);
    } catch (e) {
      failRestore(e);
      return null;
    }
  };
  // What the restorer still holds, flushed ahead of any in-band error frame.
  const flushRestorer = () => {
    if (!piiRestorer || restoreFailed) return;
    try {
      writeOut(piiRestorer.finish());
      counters.piiRestored(piiRestorer.misses);
    } catch (e) {
      failRestore(e);
    }
  };

  upRes.on('data', (raw) => {
    readUpstream(raw);
    writeOut(restore(raw));
  });

  upRes.on('end', () => {
    if (stream) feedLines(decoder.decode(), 0, true);
    flushRestorer();
    // On a sealed response writeOut QUEUES on writeChain, so the end must be
    // scheduled after every frame this handler may still add — the in-band
    // error frame below — or that frame lands behind res.end() and is lost.
    const endNow = () => {
      if (!res.writableEnded) res.end();
    };
    const endAfterWrites = () => writeChain.then(endNow).catch(endNow);
    if (clientGone || restoreFailed) {
      if (clientGone) endAfterWrites();
      settleNow();
      return;
    }
    if (stream && extractor.terminal === 'error') {
      // The upstream said so in-band; the frame went through verbatim.
      traceRec.setStreamEnd('upstream_error');
      settleFailureCode ??= ERROR_CODES.UPSTREAM_ERROR_STATUS;
      reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: false,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: 'openrouter',
        upstream_status: attempt.statusCode,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    } else if (stream && !extractor.completed) {
      // Ended with no message_stop and no error event: the generation was
      // cut short upstream. Told in-band so the client does not read a
      // truncated answer as a complete one.
      traceRec.setStreamEnd('upstream_error');
      settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
      writeOut(Buffer.from(d.streamErrorFrame(), 'utf8'));
      reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: false,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: 'openrouter',
        upstream_status: attempt.statusCode,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    } else {
      traceRec.setStreamEnd(
        auth.max_tokens_cap && d.capHit(extractor) ? 'cap_hit' : 'clean',
      );
    }
    endAfterWrites();
    settleNow();
  });
  upRes.on('error', (e) => {
    log(`${d.name} upstream stream error: ${e.message}`);
    if (clientGone || restoreFailed) {
      if (clientGone && !res.writableEnded) res.end();
      settleNow();
      return;
    }
    flushRestorer();
    if (restoreFailed) {
      settleNow();
      return;
    }
    traceRec.setStreamEnd('upstream_error');
    settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
    reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
      request_id: requestId,
      settle_id: settleId,
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: 'openrouter',
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    if (stream) writeOut(Buffer.from(d.streamErrorFrame(), 'utf8'));
    const endNow = () => {
      if (!res.writableEnded) res.end();
    };
    writeChain.then(endNow).catch(endNow);
    settleNow();
  });
}

/**
 * `POST /v1/messages/count_tokens` (#275): Anthropic's free, exact count,
 * answered from the enclave with its own Anthropic key so the prompt Claude
 * Code sends twice per session never leaves the enclave in the clear.
 *
 * The caller's PPQ credential is checked by hp's /authorize (it also resolves
 * the model to the first-party id, on the Anthropic direct candidate);
 * nothing is spent and nothing settles. A model with no first-party id gets
 * a clean 404 in the dialect, as hp answers: an invented number would be
 * worse than none.
 */
async function handleCountTokens(req, res) {
  const finalize = counters.beginRequest();
  // Bounded once for every egress (trace.mjs resolveRequestId): the caller's
  // id only in the accepted shape, else one minted here.
  const { requestId } = resolveRequestId(req.headers['x-request-id']);
  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  if (!creditId && !authHeader) {
    finalize('unauthenticated');
    return sendDialectError(
      res,
      MESSAGES_DIALECT,
      401,
      'Missing credentials. Send a PPQ API key as `x-api-key: <key>` or `Authorization: Bearer <key>`.',
    );
  }
  let body;
  let ehbpCtx = null;
  try {
    const rawBody = await readRawBody(req, MESSAGES_MAX_REQUEST_BODY_BYTES);
    const encapKey = req.headers['ehbp-encapsulated-key'];
    if (encapKey) {
      if (!ehbpRecipient) throw new Error('EHBP not initialised');
      const opened = await ehbpRecipient.openRequest(String(encapKey), rawBody);
      body = JSON.parse(opened.plaintext.toString('utf8'));
      ehbpCtx = { exportedSecret: opened.exportedSecret, requestEnc: opened.requestEnc };
    } else {
      body = JSON.parse(rawBody.toString('utf8'));
    }
  } catch (e) {
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendDialectError(res, MESSAGES_DIALECT, 400, unreadableBodyMessage(e));
  }
  if (!body || typeof body !== 'object' || typeof body.model !== 'string' || !body.model) {
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendDialectError(res, MESSAGES_DIALECT, 400, 'model: Field required');
  }
  // `pii_redaction`: the count is the whole prompt sent to Anthropic,
  // and a redacted one would cost a detector call on a request that never
  // settles and count placeholders, not the prompt. So `true` is refused
  // before anything leaves; `false` is stripped and counted; anything else is
  // a 400, as on every other path.
  const piiFlag = takePiiFlag(body);
  if (piiFlag === 'invalid' || piiFlag === 'on') {
    const code = piiFlag === 'on' ? PII_ERRORS.UNSUPPORTED_ENDPOINT : PII_ERRORS.INVALID;
    finalize(code);
    return sendPiiDialectError(res, MESSAGES_DIALECT, 400, code);
  }
  const port = Number(process.env.ANTHROPIC_PORT || 0);
  if (!port || !UPSTREAM_KEYS.anthropic) {
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendDialectError(res, MESSAGES_DIALECT, 503, 'Token counting is not available on this deployment.');
  }
  // Credential + model resolution only: a zero measure, no cap, and the
  // `count_tokens` intent, on which hp skips its balance gate (nothing is
  // spent; its own count_tokens needs no positive balance either). An hp
  // build that predates the intent applies the gate as to any authorize.
  const auth = await authorizeWithHorsepower(
    req.headers,
    body.model,
    undefined,
    0,
    { endpoint: MESSAGES_ENDPOINT, intent: COUNT_TOKENS_INTENT, input_bytes: 0, message_count: 0, image_parts: 0, file_bytes: 0, audio_bytes: 0, url_parts: 0, input_tokens_o200k: 0 },
    req.socket?.clientIp,
    requestId,
    // No balance gate on hp's side, so no balance backoff on ours: a
    // credential held for chat is still allowed to count tokens (hp #1022).
    { localBalanceBackoff: false },
  );
  if (!auth.ok) {
    const code =
      auth.failure === 'timeout'
        ? ERROR_CODES.AUTHORIZE_TIMEOUT
        : auth.failure === 'unreachable'
          ? ERROR_CODES.AUTHORIZE_UNREACHABLE
          : ERROR_CODES.AUTHORIZE_REJECTED;
    finalize(code);
    return sendDialectError(res, MESSAGES_DIALECT, auth.status || 402, dialectMessageOf(auth.body, 'not authorized'), authRefusalHeaders(auth));
  }
  // The first-party id: hp's Anthropic direct candidate when it offers one,
  // else derived from the slug (messages.mjs); a non-Claude model has none.
  const firstPartyId = anthropicFirstPartyId(auth.resolved_model || body.model, auth.upstreams);
  if (!firstPartyId) {
    finalize(ERROR_CODES.MODEL_REJECTED);
    return sendDialectError(
      res,
      MESSAGES_DIALECT,
      404,
      `Token counting is available for Anthropic models only; ${body.model} has no first-party id.`,
      'not_found_error',
    );
  }
  const bodyStr = JSON.stringify(projectCountTokensBody(body, firstPartyId));
  const headers = {
    host: cfg.anthropicHost,
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(bodyStr),
    'x-api-key': UPSTREAM_KEYS.anthropic,
    'anthropic-version': typeof req.headers['anthropic-version'] === 'string' ? req.headers['anthropic-version'] : '2023-06-01',
  };
  if (typeof req.headers['anthropic-beta'] === 'string') headers['anthropic-beta'] = req.headers['anthropic-beta'];
  const attempt = await attemptUpstream(
    { host: '127.0.0.1', port, servername: cfg.anthropicHost, method: 'POST', path: COUNT_TOKENS_UPSTREAM_PATH, headers },
    bodyStr,
  );
  if (attempt.error || !attempt.res) {
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendDialectError(res, MESSAGES_DIALECT, 502, 'upstream unreachable');
  }
  let answer;
  try {
    answer = await readRawBody(attempt.res, MAX_ERROR_BODY_BYTES);
  } catch {
    finalize(ERROR_CODES.STREAM_FAILED);
    return sendDialectError(res, MESSAGES_DIALECT, 502, 'upstream response unreadable');
  }
  const out = attempt.ok ? answer : Buffer.from(sanitizeUpstreamErrorBody(answer.toString('utf8')), 'utf8');
  finalize(attempt.ok ? 'clean' : ERROR_CODES.UPSTREAM_ERROR_STATUS);
  try {
    const respHeaders = { 'content-type': attempt.res.headers['content-type'] || 'application/json' };
    let outBody = out;
    if (ehbpCtx) {
      const respEnc = await ehbpRecipient.responseEncryptor(ehbpCtx.exportedSecret, ehbpCtx.requestEnc);
      respHeaders['Ehbp-Response-Nonce'] = respEnc.responseNonceHex;
      outBody = await respEnc.encrypt(out);
    }
    res.writeHead(attempt.statusCode, respHeaders);
    res.end(outBody);
  } catch (e) {
    log(`count_tokens response sealing failed: ${e.message}`);
    sendDialectError(res, MESSAGES_DIALECT, 502, 'response sealing failed');
  }
}

/**
 * Class A of #210: `POST /private/v1/chat/completions` — a body the CLIENT
 * sealed to Tinfoil's key. This is horse-power's `/private/*` relay, moved into
 * measured code, and it must be indistinguishable from it on the wire: every
 * published ppq-private-mode release, the Tinfoil SDK and the web app post
 * here unchanged.
 *
 * The enclave cannot read the body and does not try. It authorizes on the
 * cleartext headers, swaps the caller's PPQ credential for its own Tinfoil key,
 * relays the ciphertext, re-emits the router's `Ehbp-Response-Nonce` and
 * usage line (a header on JSON, announced and appended as a trailer on a
 * stream), and settles from that line. No receipt: there is no plaintext
 * stream to write one into.
 *
 * Every early return names its outcome through `finalize`, as chatCompletion
 * does, so /health's by_outcome invariant holds here too.
 */
async function handlePrivateRelay(req, res) {
  const finalize = counters.beginRequest();
  const ctx = {};
  try {
    await privateRelay(req, res, finalize, ctx);
  } catch (e) {
    finalize(ERROR_CODES.INTERNAL_ERROR);
    if (e && typeof e === 'object') {
      e.reportFields = handlerFailureFields(ctx, ctx.traceRec ? traceOf(ctx.traceRec) : undefined);
    }
    throw e;
  }
}

const MISSING_ENCRYPTION_MESSAGE =
  'This endpoint only accepts requests whose body is EHBP-sealed to the private enclave ' +
  '(the Ehbp-Encapsulated-Key header is missing). Seal with the ppq-private-mode proxy or ' +
  'the Tinfoil SDK, or send the private/* model to /v1/chat/completions, which seals it for you.';

async function privateRelay(req, res, finalize, ctx = {}) {
  // Bounded once for every egress (trace.mjs resolveRequestId): the caller's
  // id only in the accepted shape, else one minted here.
  const { requestId } = resolveRequestId(req.headers['x-request-id']);
  const settleId = randomUUID();
  ctx.requestId = requestId;
  ctx.settleId = settleId;

  const traceRec = createTraceRecorder();
  traceRec.setClient({
    requestId: req.headers['x-request-id'],
    userAgent: req.headers['user-agent'],
    clientIp: req.socket?.clientIp,
  });
  ctx.traceRec = traceRec;
  traceRec.setEnclave({
    version: ENCLAVE_VERSION,
    worker: cluster.isWorker ? cluster.worker.id : 0,
    box: ENCLAVE_BOX_ID || undefined,
  });
  // Sealed by definition; whether it streams is only known from the answer.
  traceRec.setEhbp(true);
  counters.ehbp();
  // `memory` is the web app's extraction pass over a private model; hp files
  // it apart from a chat turn. Forwarded as the closed set the settle records.
  const querySource = querySourceOf(req.headers);

  // The same three credential headers the chat path and hp's relay accept.
  const creditId = req.headers['x-credit-id'];
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  if (!creditId && !authHeader) {
    finalize('unauthenticated');
    return sendJson(res, 401, {
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header',
    });
  }
  // The model the caller CLAIMS (a cleartext header — the body is opaque).
  // Billing never trusts it: the settle carries the router's attested model
  // and hp prices from that; this only drives the balance pre-flight.
  const model = claimedPrivateModel(req.headers);
  // The claim must still be a private/* id: the sealed body goes to Tinfoil
  // whatever it says, so a public claim would run the balance pre-flight
  // against the wrong model.
  if (!isPrivateModel(model)) {
    finalize(ERROR_CODES.MODEL_REJECTED);
    return sendJson(res, 400, {
      error: {
        message: `X-Private-Model must name a private/* model (got ${JSON.stringify(String(model).slice(0, 80))})`,
        type: 'invalid_request_error',
        code: 'invalid_model',
      },
    });
  }
  const port = UPSTREAM_PORTS[cfg.tinfoilHost];
  const key = UPSTREAM_KEYS.tinfoil;
  if (!port || !key) {
    log('private relay: no Tinfoil tunnel or key on this box');
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      provider: TINFOIL_PROVIDER,
      upstream_status: 0,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendJson(res, 503, { error: 'Private inference is not available on this enclave' });
  }

  // Authorize BEFORE spending the Tinfoil key, and BEFORE the seal check
  // below. No input measure: the body is sealed, so hp runs the plain balance
  // check its relay always ran. The order matters for the web app: its SDK
  // cannot read a plaintext 401/402 through the sealed channel and re-probes
  // WITHOUT a body to learn the status, so a credential or balance refusal
  // must be answerable to a body-less, unsealed request.
  const auth = await authorizeWithHorsepower(
    req.headers,
    model,
    undefined,
    undefined,
    undefined,
    req.socket?.clientIp,
    requestId,
    { settleId },
  );
  traceRec.mark('authorized');
  if (!auth.ok) {
    const code =
      auth.failure === 'timeout'
        ? ERROR_CODES.AUTHORIZE_TIMEOUT
        : auth.failure === 'unreachable'
          ? ERROR_CODES.AUTHORIZE_UNREACHABLE
          : ERROR_CODES.AUTHORIZE_REJECTED;
    // A balance backoff (hp #1022) is the system working as designed, at the
    // volume that buried real failures: not reported, only counted.
    if (!auth.backoff) {
      reportEnclaveError(code, {
        request_id: requestId,
        settle_id: settleId,
        terminal: true,
        upstream_status: auth.status,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    finalize(code);
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    }, authRefusalHeaders(auth));
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;
  // From here an unanticipated throw is reported against the billed account.
  ctx.creditId = billedCreditId;
  ctx.apiKeyId = billedApiKeyId;
  ctx.querySource = querySource;
  // Only a slug hp checked against its catalog is safe to report.
  const reportableModel = auth.resolved_model === model ? model : undefined;
  ctx.model = reportableModel;

  // A plaintext body on this route is a client that misunderstood it. Refused
  // before the body is read, with hp's exact code so client handling is unchanged.
  // Reported as terminal (horse-power #1046): hp authorized this request and
  // holds a balance reservation for it, and nothing else would release it —
  // a client that keeps sending plaintext would otherwise pile up holds
  // against the account's other, working clients until each expired. The
  // web app's body-less status probe only reaches this line when the
  // credential and balance already passed, which is rare, so the row it
  // leaves in Account Activity is a real misconfiguration, not noise.
  const encap = req.headers[ENCAP_KEY_HEADER];
  if (typeof encap !== 'string' || !encap) {
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      upstream_status: 400,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendJson(res, 400, {
      error: {
        message: MISSING_ENCRYPTION_MESSAGE,
        type: 'invalid_request_error',
        code: 'missing_encryption',
      },
    });
  }
  // Read the ciphertext whole (bounded), as hp's relay does: the router wants
  // a content-length, and nothing here parses it.
  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    log(`private relay body unreadable: ${e.message}`);
    // Reported, as chat and decisions report theirs; it never settles.
    reportEnclaveError(ERROR_CODES.REQUEST_UNREADABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: TINFOIL_PROVIDER,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.REQUEST_UNREADABLE);
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }

  traceRec.setRoute({
    chosen: TINFOIL_PROVIDER,
    upstreamHost: cfg.tinfoilHost,
    apiStyle: 'tinfoil-relay',
    skipped: [],
    failed: [],
  });
  const opts = {
    host: '127.0.0.1',
    port,
    servername: cfg.tinfoilHost,
    method: 'POST',
    path: '/v1/chat/completions',
    headers: relayHeaders(req.headers, { host: cfg.tinfoilHost, key, bodyLength: rawBody.length }),
  };
  const attempt = await attemptUpstream(opts, rawBody);
  if (!attempt.res) {
    log(`private relay upstream error: ${attempt.error?.message}`);
    reportEnclaveError(ERROR_CODES.UPSTREAM_UNREACHABLE, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: TINFOIL_PROVIDER,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_UNREACHABLE);
    return sendJson(res, 502, { error: 'Private inference enclave unreachable' });
  }
  traceRec.mark('upstreamHeaders');
  counters.provider(TINFOIL_PROVIDER);
  const upRes = attempt.res;
  const statusCode = attempt.statusCode || 200;
  // Only a 2xx answer is ever settled (conclude() below). Every failure report
  // from here on is the request's final one exactly when it will not settle.
  const relaySettles = statusCode >= 200 && statusCode < 300;
  if (!relaySettles) {
    // Passed through as the router's own answer (a key-config 422, a 429, a
    // stray 3xx, ...) and reported, since it never settles.
    // A 422 is a router key rotation: the client refetches the bundle next, so
    // it must not get the cached, now-stale one.
    if (statusCode === 422) tinfoilBundleCache.invalidate();
    reportEnclaveError(ERROR_CODES.UPSTREAM_ERROR_STATUS, {
      request_id: requestId,
      settle_id: settleId,
      terminal: true,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: TINFOIL_PROVIDER,
      upstream_status: statusCode,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
    finalize(ERROR_CODES.UPSTREAM_ERROR_STATUS);
  }

  const { headers: respHeaders, streaming } = relayResponseHeaders(upRes);
  traceRec.setStreaming(streaming);
  res.writeHead(statusCode, respHeaders);
  counters.streamOpened();

  let settled = false;
  let clientGone = false;
  // What the relay wrote to the client, in sealed bytes and upstream data
  // chunks: the only measure of a delivered answer this path can take, and
  // the one an abort before the usage line settles from (see conclude).
  let relayedBytes = 0;
  let relayedChunks = 0;
  // A 2xx answer that broke mid-stream still settles; the settle says so.
  let settleFailureCode;
  const conclude = () => {
    if (settled) return;
    settled = true;
    traceRec.mark('end');
    counters.streamClosed();
    finalize(traceRec.streamEnd());
    if (!relaySettles) return;
    ctx.settleStarted = true;
    const metrics = parseUsageMetrics(usageMetricsOf(upRes));
    // The client hung up before the router's usage line (it only ever arrives
    // at the end of the stream), keeping everything streamed so far. Until the
    // Oct 17-19 security reports this settled 0/0 "as hp's relay behaved":
    // apienz reproduced it on production 5/5 — 8-24 KB of real answer per
    // run, rows of `in=0 out=0 $0` — and hp's zero-cost fallbacks skip
    // tinfoil rows, so nothing priced it. Settle a floor from what was
    // delivered instead (abortedRelayOutputFloor), marked `counted` the way
    // the chat path marks its own count, so a served answer is never free.
    // Input stays 0: the sealed body cannot be measured here (the relay
    // authorizes with no input measure either); hp holds the pre-flight it
    // ran and prices that half on `stream_end: client_abort`.
    const abortedBeforeUsage = clientGone && !metrics;
    const flooredOutput = abortedBeforeUsage
      ? abortedRelayOutputFloor({ chunks: relayedChunks, bytes: relayedBytes })
      : 0;
    if (!metrics && !abortedBeforeUsage) {
      // A served answer nothing can price: the router emits the line on every
      // completion, so its absence is a router-version skew or a truncated
      // stream. Reported, AND still settled below with zero counts (the body
      // is ciphertext; there is nothing to count) so hp files a visible $0
      // row the way the decisions path does — never a silently free answer.
      reportEnclaveError(ERROR_CODES.TINFOIL_USAGE_MISSING, {
        request_id: requestId,
        settle_id: settleId,
        terminal: false,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: TINFOIL_PROVIDER,
        upstream_status: statusCode,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    reportSettlement({
      request_id: String(requestId),
      settle_id: settleId,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      failure_code: settleFailureCode,
      // The claimed id keys the balance and the row's provenance; hp bills on
      // `served_model`, the attested one, and records both.
      model,
      input_tokens: metrics ? metrics.promptTokens : 0,
      output_tokens: metrics ? metrics.completionTokens : flooredOutput,
      // 'upstream' when the router's line priced it; 'counted' when the row is
      // the enclave's own floor on an aborted stream (hp tells the two apart,
      // exactly as for the chat path's local count). A counted row has no
      // attested `served_model`: hp's priceTinfoilSettle then bills the counts
      // fail-closed at the dearest private rate (tinfoilPricing.maxPrivateCost),
      // never from the client's claim and never at $0.
      usage_source: abortedBeforeUsage ? 'counted' : 'upstream',
      total_cost_usd: 0,
      cost_source: TINFOIL_COST_SOURCE,
      generation_id: '',
      query_source: querySource,
      // Content-free size of what went through, on every relay settle: hp can
      // calibrate bytes-per-token on rows the router priced and apply it to
      // the aborted ones the floor above under-counts. Sealed bytes only.
      sealed_request_bytes: rawBody.length,
      relayed_bytes: relayedBytes,
      relayed_chunks: relayedChunks,
      cache_read_tokens: metrics?.cachedPromptTokens,
      // Cleartext analytics flag the web app sets beside a sealed body: the
      // fact that a search was asked for, never the query (hp relay parity).
      is_online: req.headers['x-private-web-search'] === 'true',
      is_free_model: false,
      auto_model: false,
      provider: TINFOIL_PROVIDER,
      upstream_model: routerModelId(model),
      served_model: metrics?.model,
      route: 'direct',
      route_bail_reason: 'none',
      direct_provider: TINFOIL_PROVIDER,
      // Creator payout (hp relay parity): a registered tool id pays its
      // creator once the charge lands. Shape-checked here AND at hp.
      tool_id: toolIdOf(req.headers) ?? undefined,
      trace: traceOf(traceRec),
    });
  };

  upRes.on('data', (chunk) => {
    traceRec.addBytes(chunk.length);
    traceRec.mark('firstByte');
    relayedBytes += chunk.length;
    relayedChunks += 1;
    res.write(chunk);
  });
  // The client went away: stop the router working for nobody. The router's
  // usage line only ever arrives at the end, so an aborted relay has no
  // trailer to settle from; conclude() (reached through the upstream 'error'
  // the destroy raises) settles the delivered floor instead.
  res.on('close', () => {
    if (settled) return;
    clientGone = true;
    traceRec.setStreamEnd('client_abort');
    finalize(ERROR_CODES.CLIENT_ABORT);
    upRes.destroy(new Error('client aborted; upstream cancelled'));
    // A non-2xx answer was already reported as the request's one final
    // outcome, with its status; a close while its body relays adds nothing.
    if (!relaySettles) return;
    reportEnclaveError(ERROR_CODES.CLIENT_ABORT, {
      request_id: requestId,
      settle_id: settleId,
      terminal: false,
      credit_id: billedCreditId,
      api_key_id: billedApiKeyId,
      model: reportableModel,
      provider: TINFOIL_PROVIDER,
      query_source: querySource,
      trace: traceOf(traceRec),
    });
  });
  upRes.on('end', () => {
    const trailer = upRes.trailers?.[USAGE_METRICS_HEADER];
    if (streaming && typeof trailer === 'string' && trailer) {
      res.addTrailers({ 'X-Tinfoil-Usage-Metrics': trailer });
    }
    if (!res.writableEnded) res.end();
    traceRec.setStreamEnd('clean');
    conclude();
  });
  upRes.on('error', (e) => {
    log(`private relay stream error: ${e.message}`);
    if (clientGone) {
      if (!res.writableEnded) res.end();
      conclude();
      return;
    }
    traceRec.setStreamEnd('upstream_error');
    // As on close: a non-2xx answer's final report is already out, and its
    // status says more than a broken error body would.
    if (relaySettles) {
      settleFailureCode ??= ERROR_CODES.STREAM_FAILED;
      reportEnclaveError(ERROR_CODES.STREAM_FAILED, {
        request_id: requestId,
        settle_id: settleId,
        terminal: false,
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: reportableModel,
        provider: TINFOIL_PROVIDER,
        query_source: querySource,
        trace: traceOf(traceRec),
      });
    }
    if (!res.writableEnded) res.end();
    conclude();
  });
}

/**
 * `GET|POST /private/attestation` — the Tinfoil attestation bundle for the
 * PINNED router, relayed from ATC. What every Tinfoil SDK client (the proxy,
 * the web app) fetches before sealing. Not this enclave's own attestation —
 * that is `/attestation` — and not the key this enclave verified for Class B:
 * the client verifies the bundle itself, which is the whole point of Class A.
 */
async function handlePrivateAttestation(req, res) {
  if (!TINFOIL_ATC_PORT) {
    return sendJson(res, 503, { error: 'Private inference service unreachable' });
  }
  try {
    const bundle = await tinfoilBundleCache.get();
    return sendJson(res, 200, bundle);
  } catch (e) {
    log(`private attestation relay failed: ${e.message}`);
    return sendJson(res, 502, { error: 'Private inference service unreachable' });
  }
}

/**
 * `GET /private/.well-known/hpke-keys` — the router's RFC 9458 key config,
 * relayed byte for byte (`application/ohttp-keys`). The ehbp client fetches it
 * on a key-config mismatch to re-derive; the attested bundle is what a client
 * should trust, this is the recovery path.
 */
function handlePrivateHpkeKeys(req, res) {
  const port = UPSTREAM_PORTS[cfg.tinfoilHost];
  if (!port) return sendJson(res, 503, { error: 'Private inference service unreachable' });
  const up = https.request(
    {
      host: '127.0.0.1',
      port,
      servername: cfg.tinfoilHost,
      method: 'GET',
      path: '/.well-known/hpke-keys',
      headers: { host: cfg.tinfoilHost, accept: 'application/ohttp-keys' },
      timeout: 15_000,
    },
    (upRes) => {
      const headers = {};
      const ct = upRes.headers['content-type'];
      if (typeof ct === 'string') headers['content-type'] = ct;
      res.writeHead(upRes.statusCode || 502, headers);
      upRes.pipe(res);
      upRes.on('error', () => res.destroy());
    },
  );
  up.on('timeout', () => up.destroy(new Error('hpke-keys timeout')));
  up.on('error', (e) => {
    log(`private hpke-keys relay failed: ${e.message}`);
    if (!res.headersSent) sendJson(res, 502, { error: 'Private inference service unreachable' });
    else res.destroy();
  });
  res.on('close', () => up.destroy());
  up.end();
}

function requestRouter(req, res) {
  // Not ours → horse-power, verbatim, before any header of ours is set: it
  // answers its own preflights and its CORS allows every method, where the
  // block below would tell a browser that PUT and DELETE do not exist.
  // Only for connections that arrived through the PROXY-protocol port (the
  // api path, proxyListener.mjs marks them): enclave.ppq.ai's plain port
  // keeps its 404s, so configuring a passthrough host never widens what that
  // hostname serves, and no proxied request leaves without a client address
  // horse-power can rate-limit and geo-block by.
  if (passthrough && req.socket?.viaProxyProtocol) {
    const decision = routeDecision(req.method, req.url);
    if (decision === 'refuse') {
      // A near-miss spelling of a route we serve (`/v1/chat/completions/`,
      // `/V1/Chat/Completions`, `//v1/...`, `%76%31`): horse-power's Express
      // would have served it as the real thing, outside the enclave and with
      // no receipt (Oct 17-19 security reports; see canonicalPath). Answered
      // here, content-free, and never proxied. The path is logged with its
      // length only: it is caller text.
      log(`refused near-miss of an enclave route: ${req.method} (${String(req.url || '').length} chars)`);
      return sendJson(res, 404, { error: { message: 'Not found', code: 404 } });
    }
    if (decision === 'proxy') return passthrough.handle(req, res);
  }
  // CORS for browser clients.
  res.setHeader('access-control-allow-origin', '*');
  // `*` never covers Authorization (Fetch spec): it must be named, or a
  // browser client sending a bearer key fails its preflight.
  res.setHeader('access-control-allow-headers', '*, Authorization');
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
  // X-Tinfoil-Usage-Metrics: the private relay re-emits the router's usage
  // line as horse-power did, so a browser client that read it there still can.
  // The routing receipt of a non-streaming response rides these two headers
  // (receipt.mjs); a browser client cannot verify what it cannot read.
  res.setHeader(
    'access-control-expose-headers',
    'Ehbp-Response-Nonce, X-Tinfoil-Usage-Metrics, Ppq-Routing-Receipt, Ppq-Routing-Receipt-Sig',
  );
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = (req.url || '').split('?')[0];
  if (req.method === 'GET' && url === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      // Where authorize/settle and the passthrough go, as a measured fact:
      // `pinned` + the name, `unset` (arm dark), or `rejected` + the name the
      // init blob tried to use (hpHosts.mjs). A rejection here is a box whose
      // parent is misconfigured or hostile; either way it serves no chat.
      hp_hosts: { settle: hpSettleHost, passthrough: hpPassthroughHost },
      keyLoaded: Boolean(OPENROUTER_API_KEY),
      bedrockCredsLoaded: Boolean(bedrockCreds.get()),
      key_sources: keySources(),
      acme_store: acmeStoreSelfTest,
      // What is actually being SERVED, not merely what sealing can do.
      acme_certificates: issuedCertificateSummary(),
      // The DEFAULT context: what a TLS 1.2, bare-IP or unknown-SNI client is
      // served. `boot: true` after a certificate is installed means #195 is
      // back -- `acme_certificates` alone cannot show that, which is how it hid.
      served_default: servedIdentity
        ? { spki_sha256: servedIdentity.currentSpkiSha256(), boot: servedIdentity.isBoot() }
        : null,
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
      // Whether a passthrough host is configured: routes the enclave does not
      // serve are then proxied to horse-power for connections on the
      // PROXY-protocol port (api.ppq.ai) and still answered 404 on the plain
      // port (enclave.ppq.ai). A config fact, identical on every worker.
      passthrough: Boolean(passthrough),
      // Whether this enclave also listens on a PROXY-protocol port (the api
      // path); a config fact, identical on every worker.
      proxy_protocol: cfg.ppPort > 0,
      workers: WORKER_COUNT,
      worker: cluster.isWorker ? cluster.worker.id : 0,
      pid: process.pid,
      // Per-WORKER request counters (counters.mjs): enum keys, integers, nothing
      // about any request. Sum across workers for a box-wide view.
      counters: counters.snapshot({ settleQueued: settleQueue.size() }),
      // PII redaction counters (counts, latency buckets, failure reasons,
      // restoration misses): never a surface, a placeholder or the mapping.
      pii_redaction: counters.piiSnapshot(),
      // Tinfoil's router key for Class B private/* requests (#210): whether
      // one has been verified, when, and against which measurement. Never the
      // key. `configured: false` means no ATC tunnel — private/* requests on
      // the chat route are refused on this box.
      tinfoil: tinfoilAttestor.state(),
      // The PII detector's attestation, same shape: verified or not, when,
      // and the measurement. Never the key, never text.
      pii_detector_attestation: piiDetectorAttestor.state(),
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
    (url === '/v1/decisions' || url === '/decisions' || url === '/v1/systemone')
  ) {
    return handleDecisions(req, res).catch((e) => {
      log(`decisions handler error: ${e.message}`);
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, e?.reportFields || {});
      if (!res.headersSent)
        sendJson(res, 500, { error: { message: 'internal', code: 500 } });
    });
  }
  // The Anthropic Messages dialect and its count endpoint, in-enclave (#275).
  if (req.method === 'POST' && url === MESSAGES_PATH) {
    return handleMessages(req, res).catch((e) => {
      log(`messages handler error: ${e.message}`);
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, e?.reportFields || {});
      if (!res.headersSent) sendDialectError(res, MESSAGES_DIALECT, 500, 'internal');
      else if (!res.writableEnded) res.end();
    });
  }
  // The OpenAI Responses API, in-enclave (#280), on the same relay.
  if (req.method === 'POST' && RESPONSES_PATHS.includes(url)) {
    return handleDialectRelay(req, res, RESPONSES_DIALECT).catch((e) => {
      log(`responses handler error: ${e.message}`);
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, e?.reportFields || {});
      if (!res.headersSent) sendDialectError(res, RESPONSES_DIALECT, 500, 'internal');
      else if (!res.writableEnded) res.end();
    });
  }
  if (req.method === 'POST' && url === COUNT_TOKENS_PATH) {
    return handleCountTokens(req, res).catch((e) => {
      log(`count_tokens handler error: ${e.message}`);
      if (!res.headersSent) sendDialectError(res, MESSAGES_DIALECT, 500, 'internal');
      else if (!res.writableEnded) res.end();
    });
  }
  // The private/* relay and its two helper routes (#210, tinfoil.mjs). Path
  // shapes and answers mirror horse-power's `/private/*` exactly: every
  // published ppq-private-mode release and the web app post here unchanged.
  if (
    req.method === 'POST' &&
    (url === '/private/v1/chat/completions' || url === '/private/chat/completions')
  ) {
    return handlePrivateRelay(req, res).catch((e) => {
      log(`private relay error: ${e.message}`);
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, e?.reportFields || {});
      if (!res.headersSent)
        sendJson(res, 500, { error: { message: 'internal', code: 500 } });
    });
  }
  if ((req.method === 'GET' || req.method === 'POST') && url === '/private/attestation') {
    return handlePrivateAttestation(req, res).catch((e) => {
      log(`private attestation relay error: ${e.message}`);
      if (!res.headersSent) sendJson(res, 502, { error: 'Private inference service unreachable' });
    });
  }
  if (req.method === 'GET' && url === '/private/.well-known/hpke-keys') {
    return handlePrivateHpkeKeys(req, res);
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
      reportEnclaveError(ERROR_CODES.INTERNAL_ERROR, e?.reportFields || {});
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
  if (storeKeyIdStatus() === 'foreign') {
    // The parent named a CMK this image does not pin (acmeStore.mjs,
    // STORE_KEY_IDS). Refused without a KMS call: a store under a key of the
    // parent's choosing could carry an identity of the parent's choosing, and
    // the attestation would then vouch for it. The box serves a fresh
    // identity and orders afresh instead, and /health says why.
    acmeStoreSelfTest = `failed:${SELF_TEST_REASONS.KEY_NOT_PINNED}`;
    log('acme-store: REFUSED — init named a CMK this image does not pin; store is inert');
  } else {
    acmeStoreSelfTest = await selfTest({ kms: storeKms, log });
    if (!storeKms) log('acme-store: not configured (no CMK id); store is inert');
  }

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

  servedIdentity = createServedIdentity({ key: readFileSync(cfg.tlsKeyPath), cert: certPem, log });

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
      installIssued(cached.payload.domains?.length ? cached.payload.domains : [domain], {
        key: cached.payload.key,
        cert: cached.payload.cert,
      });
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
    const server = https.createServer(tlsOptions(), requestRouter);
    servedIdentity.attach(server);
    // WebSocket and any other Upgrade: only horse-power has such routes, and
    // only the api port proxies them (same gate as requestRouter). Elsewhere
    // the connection is closed, as Node does with no upgrade listener.
    if (passthrough) server.on('upgrade', (req, socket, head) => (socket.viaProxyProtocol ? passthrough.upgrade(req, socket, head) : socket.destroy()));
    // Pay the tokenizer load (~120 ms) now, not on the first user's request.
    void loadTokenizer();
    if (placeOrder) server.on('listening', placeOrder);
    server.listen(cfg.inboundPort, '127.0.0.1', () =>
      log(`enclave proxy listening (TLS) on 127.0.0.1:${cfg.inboundPort}`),
    );
    // The api path: PROXY header, then the same TLS server (proxyListener.mjs).
    // Awaited: a port that cannot bind rejects here and start() fails, rather
    // than the box serving 443 with the api path silently missing.
    if (cfg.ppPort > 0) await listenWithProxyProtocol(server, { port: cfg.ppPort, host: '127.0.0.1', log });
  } else {
    fleet.start({ onAllListening: placeOrder });
  }
}

/**
 * The one way a certificate is installed in this process: under every name it
 * covers for SNICallback, AND as the default context and signing key (#195).
 * Every site that used to call setIssuedCertificate directly goes through
 * here so the two cannot drift.
 */
function installIssued(names, creds) {
  for (const name of names) setIssuedCertificate(name, creds);
  try {
    servedIdentity?.adopt(creds);
  } catch (e) {
    // SNI still serves it under the names above; the DEFAULT stays what it
    // was and /health `served_default.boot` says so. Loud, because this is
    // #195 recurring for every TLS 1.2 client.
    log(`served-identity: certificate installed for ${names.join(', ')} but NOT as the default context: ${e.message}`);
  }
}

/**
 * Install a certificate under every name it covers, tell the workers, then
 * seal and save it with the EHBP identity. Shared by the in-enclave order and
 * the CI-driven renewal; only the PRIMARY (or the single process) calls it.
 */
async function persistIssued({ key, cert, domains: names, source }) {
  installIssued(names, { key, cert });
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

/**
 * TLS server options; identical for the single process and for every worker.
 *
 * The default context is whatever servedIdentity holds: the boot pair until an
 * ACME certificate is installed, that certificate after. SNICallback below
 * only ADDS a context to a connection -- OpenSSL keeps the default's
 * certificate selectable beside it and lets the client's cipher order choose
 * (#195) -- so the default must never be a certificate we do not want served.
 */
function tlsOptions() {
  return {
    ...servedIdentity.contextOptions(),
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
  servedIdentity = createServedIdentity({ key: readFileSync(cfg.tlsKeyPath), cert: certPem, log });

  const state = await stateP;
  // The primary already validated this identity; a failure here is a bug, and
  // a worker that cannot decrypt what the attestation advertises must not serve.
  ehbpRecipient = await EhbpRecipient.fromJSON(state.hpke);
  HPKE_PUBLIC_KEY_HEX = await ehbpRecipient.publicKeyHex();
  hpkeIdentitySource = state.hpkeIdentitySource;
  hpkeIdentityPersisted = state.hpkeIdentityPersisted;
  acmeStoreSelfTest = state.acmeStoreSelfTest;
  for (const [name, creds] of state.issued || []) installIssued([name], creds);
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
        installIssued(m.names || [], { key: m.key, cert: m.cert });
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

  const server = https.createServer(tlsOptions(), requestRouter);
  servedIdentity.attach(server);
  // WebSocket and any other Upgrade: only horse-power has such routes, and
  // only the api port proxies them (same gate as requestRouter).
  if (passthrough) server.on('upgrade', (req, socket, head) => (socket.viaProxyProtocol ? passthrough.upgrade(req, socket, head) : socket.destroy()));
  // Workers serve; the primary never tokenizes, so only they load the encoder.
  void loadTokenizer();
  const tlsListening = new Promise((resolve) =>
    server.listen(cfg.inboundPort, '127.0.0.1', () => {
      log(`cluster: worker ${cluster.worker.id} listening (TLS) on 127.0.0.1:${cfg.inboundPort}`);
      resolve();
    }),
  );
  // The api path: a second, shared port every worker accepts on, exactly like
  // the inbound port (a net.Server in a worker binds through the primary). A
  // bind failure rejects, workerMain fails, and the primary sees an exit.
  const ppListening =
    cfg.ppPort > 0
      ? listenWithProxyProtocol(server, {
          port: cfg.ppPort,
          host: '127.0.0.1',
          log: (m) => log(`cluster: worker ${cluster.worker.id} ${m}`),
        })
      : Promise.resolve();
  // Ready means BOTH ports: the primary counts this toward "all listening",
  // and a worker that answered on 443 but not yet on the api port is not ready.
  await Promise.all([tlsListening, ppListening]);
  process.send({ type: MSG.LISTENING });
}

const main = cluster.isPrimary ? start : workerMain;
main().catch((e) => {
  log(`fatal start error: ${e.message}`);
  process.exit(1);
});
