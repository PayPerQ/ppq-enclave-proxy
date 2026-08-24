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
import { readFileSync } from 'node:fs';
import { X509Certificate, createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  resolveModel,
  transformPayload,
  applySafetyIdentifier,
  applyFreeModelStrip,
  applyAutoRouterConfig,
  applyToolStrip,
} from './routing.mjs';
import { createSettleQueue, classifySettleStatus } from './settleQueue.mjs';
import { CostExtractor } from './cost.mjs';
import { Rebrander, directResponseRewriter } from './rebrand.mjs';
import { buildDirectRequest, isOpenRouter } from './upstreams.mjs';
import { buildBedrockRequest, ResponsesToChatSse } from './bedrock.mjs';
import { buildAnthropicRequest, MessagesToChatSse } from './anthropic.mjs';
import { BedrockCredsHolder } from './bedrockCreds.mjs';
import { EhbpRecipient } from './ehbp-server.mjs';

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

// EHBP recipient (HPKE keypair). Browsers HPKE-seal their request body to this
// public key, which the attestation commits to in `public_key`. Only the enclave
// holds the private key, so the host — even terminating the browser's TLS — sees
// only ciphertext. Generated once at startup.
let ehbpRecipient = null;
let HPKE_PUBLIC_KEY_HEX = '';

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
function authorizeWithHorsepower(reqHeaders, model, maxTokens) {
  return new Promise((resolve) => {
    if (!cfg.settleHost) {
      // No horse-power reachable — fail closed, do not spend the key.
      return resolve({ ok: false, status: 503, body: { error: 'authorization unavailable' } });
    }
    const payload = JSON.stringify({ model, max_tokens: maxTokens });
    const headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
      host: cfg.settleHost,
    };
    if (reqHeaders['authorization']) headers['authorization'] = reqHeaders['authorization'];
    if (reqHeaders['x-credit-id']) headers['x-credit-id'] = reqHeaders['x-credit-id'];
    if (reqHeaders['x-query-source']) headers['x-query-source'] = reqHeaders['x-query-source'];

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
            auto_router:
              body.auto_router &&
              Array.isArray(body.auto_router.allowed_models) &&
              body.auto_router.allowed_models.length > 0 &&
              typeof body.auto_router.cost_tier === 'string'
                ? {
                    allowed_models: body.auto_router.allowed_models,
                    cost_tier: body.auto_router.cost_tier,
                  }
                : null,
            // Ordered upstream candidate list (Phase 1). Absent on older hp →
            // empty, and the connector falls back to OpenRouter-only.
            upstreams: Array.isArray(body.upstreams) ? body.upstreams : [],
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

/** Fire-and-forget settlement — durable: retried on transient failure (#5). */
function reportSettlement(meta) {
  if (!cfg.settleHost) {
    log('settle skipped: SETTLE_HOST unset');
    return;
  }
  settleQueue.submit(meta);
}

async function handleChatCompletion(req, res) {
  const requestId =
    req.headers['x-request-id'] ||
    `enc-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

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
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }

  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  // Enclave-local resolution first: object->string + reject unsupported models.
  // (Full slug/alias resolution can't happen here — it needs the live catalog a
  // pinned build can't hold — so hp does it at /authorize below.)
  try {
    resolveModel(payload);
  } catch (e) {
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
  );
  if (!auth.ok) {
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    });
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;

  // Apply hp's model resolution (#2) to the neutral payload. Falls back to the
  // raw model when hp didn't resolve it (older hp). Applies to BOTH paths.
  if (typeof auth.resolved_model === 'string' && auth.resolved_model) {
    payload.model = auth.resolved_model;
  }
  const model = payload.model;
  const isFreeModel = /(:|\/)free\b/.test(model) || /free$/.test(model);

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

  // Ordered upstream candidates from hp (Phase 1). An older hp sends none → OR.
  const candidates =
    Array.isArray(auth.upstreams) && auth.upstreams.length > 0
      ? auth.upstreams
      : [{ provider: 'openrouter' }];

  // Try each in order. A DIRECT candidate must be eligible AND return 2xx, else
  // we drain it and fall to the next. OpenRouter is TERMINAL — piped regardless
  // of status (nothing follows it); only a connect error 502s.
  let chosen = null;
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
                keys: UPSTREAM_KEYS,
              });
      if (built.skip) {
        log(`direct ${cand.provider} skipped: ${built.skip}${built.offendingField ? ' ' + built.offendingField : ''}`);
        continue;
      }
      spec = { ...built, isDirect: true };
    }
    const attempt = await attemptUpstream(spec.opts, spec.bodyStr);
    if (attempt.res && (attempt.ok || terminal)) {
      chosen = { spec, res: attempt.res, statusCode: attempt.statusCode || 200 };
      break;
    }
    if (attempt.res) attempt.res.resume(); // discard the failed direct response body
    log(`upstream ${cand.provider} failed: ${attempt.statusCode || attempt.error?.message || 'unknown'}`);
    if (terminal) {
      return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
    }
  }
  if (!chosen) {
    return sendJson(res, 502, { error: { message: 'upstream unreachable', code: 502 } });
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

  upRes.on('data', (raw) => {
    const chunk = translator ? translator.feed(raw) : raw;
    if (translator && chunk.length === 0) return;
    extractor.feed(chunk);
    writeOut(rewriter.feed(chunk));
  });
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
    const usage = extractor.finish();
    // Content-free billing metadata. For a direct upstream: bill on the public
    // or_slug (so hp margins match) and report provider + wire/served model ids
    // so hp prices from the catalog rate table (no OR cost / generation id).
    reportSettlement({
      request_id: String(requestId),
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
      is_online: Boolean(basePayload.plugins?.some?.((p) => p.id === 'web')),
      is_free_model: isFreeModel,
      // The model the CALLER asked for — not the one the router landed on,
      // which travels as served_model. hp needs the former to stamp autoModel;
      // without it, enclave-served Auto traffic is invisible in reporting
      // (horse-power#790).
      //
      // Read from basePayload, i.e. AFTER hp's resolved_model is applied, and
      // that is deliberate: `auto` is an alias hp resolves to `openrouter/auto`,
      // so the resolved slug catches both spellings where the raw body would
      // catch only one. hp never resolves a non-Auto model TO openrouter/auto,
      // so there is no false positive in the other direction.
      auto_model: basePayload.model === 'openrouter/auto',
      provider: chosenDirect ? chosen.spec.provider : 'openrouter',
      upstream_model: chosenDirect ? chosen.spec.upstreamModel : undefined,
      served_model: usage.model,
    });
  });
  upRes.on('error', (e) => {
    log(`upstream stream error: ${e.message}`);
    if (!res.writableEnded) res.end();
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
async function handleAttestation(req, res) {
  const q = new URL(req.url, 'http://x').searchParams;
  const nonceHex = sanitizeNonceHex(q.get('nonce') || '');
  const args = ['--public-key', HPKE_PUBLIC_KEY_HEX, '--user-data', CERT_SPKI_SHA256_HEX];
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
    cert_spki_sha256: CERT_SPKI_SHA256_HEX,
    format: 'nsm-cose-sign1',
  });
}

function requestRouter(req, res) {
  // CORS for browser clients.
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', '*');
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
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
    });
  }
  if (req.method === 'GET' && url === '/attestation') {
    return handleAttestation(req, res).catch((e) => {
      log(`attestation error: ${e.message}`);
      if (!res.headersSent)
        sendJson(res, 500, { error: { message: 'attestation failed', code: 500 } });
    });
  }
  if (
    req.method === 'POST' &&
    (url === '/v1/chat/completions' || url === '/chat/completions')
  ) {
    return handleChatCompletion(req, res).catch((e) => {
      log(`handler error: ${e.message}`);
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
  log(`TLS cert SPKI SHA-256: ${CERT_SPKI_SHA256_HEX}`);

  // Generate the EHBP HPKE keypair; the attestation commits to its public key.
  ehbpRecipient = await EhbpRecipient.generate();
  HPKE_PUBLIC_KEY_HEX = await ehbpRecipient.publicKeyHex();
  log(`EHBP HPKE public key: ${HPKE_PUBLIC_KEY_HEX}`);

  // Bedrock creds channel: boot.sh forwards vsock:7001 to this loopback
  // listener, and passes any bedrock fields from the one-shot init blob via
  // BEDROCK_INIT_JSON so the first boot works before the host's first
  // refresh tick. Both are optional — without them the bedrock candidate is
  // simply skipped (no_tunnel_or_key).
  const credsPort = Number(process.env.CREDS_PORT || 0);
  if (credsPort > 0) {
    bedrockCreds.listen(credsPort);
    log(`bedrock creds listener on 127.0.0.1:${credsPort}`);
  }
  if (process.env.BEDROCK_INIT_JSON) {
    try {
      await bedrockCreds.applyBlob(JSON.parse(process.env.BEDROCK_INIT_JSON));
    } catch (e) {
      log(`bedrock init creds blob rejected: ${e.message}`);
    }
    delete process.env.BEDROCK_INIT_JSON;
  }

  const tlsOpts = {
    key: readFileSync(cfg.tlsKeyPath),
    cert: certPem,
    minVersion: 'TLSv1.2',
  };
  const server = https.createServer(tlsOpts, requestRouter);
  server.listen(cfg.inboundPort, '127.0.0.1', () =>
    log(`enclave proxy listening (TLS) on 127.0.0.1:${cfg.inboundPort}`),
  );
}

start().catch((e) => {
  log(`fatal start error: ${e.message}`);
  process.exit(1);
});
