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
import { resolveModel, transformPayload } from './routing.mjs';
import { CostExtractor } from './cost.mjs';
import { Rebrander } from './rebrand.mjs';

const execFileAsync = promisify(execFile);

const cfg = {
  inboundPort: Number(process.env.INBOUND_PORT || 8443),
  orPort: Number(process.env.OR_PORT || 9443),
  settlePort: Number(process.env.SETTLE_PORT || 9444),
  orHost: process.env.OPENROUTER_HOST || 'openrouter.ai',
  settleHost: process.env.SETTLE_HOST, // e.g. abc123.ngrok-free.dev
  settleSecret: process.env.ENCLAVE_SETTLE_SECRET || '',
  tlsKeyPath: process.env.TLS_KEY_PATH || '/app/tls/key.pem',
  tlsCertPath: process.env.TLS_CERT_PATH || '/app/tls/cert.pem',
};

// The OpenRouter API key is injected at boot by boot.sh after an
// attestation-gated KMS Decrypt. It never touches disk on the parent.
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

// SHA-256 of this enclave's TLS certificate SubjectPublicKeyInfo (DER). The
// attestation document commits to this value in its `public_key` field, so a
// client can prove the TLS endpoint it's talking to IS this attested enclave.
// Computed once at startup from the boot-generated cert.
let CERT_SPKI_SHA256_HEX = '';

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

function readJsonBody(req, limitBytes = 25 * 1024 * 1024) {
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
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(new Error('invalid JSON body'));
      }
    });
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

/** Fire-and-forget settlement POST to horse-power over the vsock tunnel. */
function reportSettlement(meta) {
  if (!cfg.settleHost) {
    log('settle skipped: SETTLE_HOST unset');
    return;
  }
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
    let b = '';
    resp.on('data', (d) => (b += d));
    resp.on('end', () =>
      log(`settle status=${resp.statusCode} req=${meta.request_id}`),
    );
  });
  r.on('error', (e) => log(`settle error req=${meta.request_id}: ${e.message}`));
  r.write(payload);
  r.end();
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

  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }

  const querySource = req.headers['x-query-source'] === 'ui' ? 'ui' : 'api';

  // Routing / transforms that need cleartext (must run here, post-TLS).
  try {
    resolveModel(payload);
    transformPayload(payload);
  } catch (e) {
    return sendJson(res, 400, { error: { message: e.message, code: 400 } });
  }
  const model = payload.model;
  const isFreeModel = /(:|\/)free\b/.test(model) || /free$/.test(model);

  // Gate on horse-power authorization BEFORE spending the company key. This
  // authenticates the caller (API key or credit_id) and checks balance; without
  // it, anyone reaching the enclave could get free inference on the shared key.
  const auth = await authorizeWithHorsepower(
    req.headers,
    model,
    payload.max_tokens ?? payload.max_completion_tokens,
  );
  if (!auth.ok) {
    return sendJson(res, auth.status || 402, auth.body || {
      error: { message: 'not authorized', code: auth.status || 402 },
    });
  }
  const billedCreditId = auth.credit_id;
  const billedApiKeyId = auth.api_key_id;

  // Forward to OpenRouter over the vsock tunnel.
  const orPayload = JSON.stringify(payload);
  const orOpts = {
    host: '127.0.0.1',
    port: cfg.orPort,
    servername: cfg.orHost,
    method: 'POST',
    path: '/api/v1/chat/completions',
    headers: {
      host: cfg.orHost,
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(orPayload),
      authorization: `Bearer ${OPENROUTER_API_KEY}`,
      'http-referer': 'https://ppq.ai/',
      'x-title': 'PPQ.AI',
    },
  };

  const extractor = new CostExtractor({ isFreeModel });
  const rebrander = new Rebrander();

  const upstream = https.request(orOpts, (orRes) => {
    res.writeHead(orRes.statusCode || 200, {
      'content-type': orRes.headers['content-type'] || 'application/json',
      'transfer-encoding': 'chunked',
    });

    orRes.on('data', (chunk) => {
      extractor.feed(chunk); // inspect for usage/cost
      res.write(rebrander.feed(chunk)); // OPENROUTER -> PPQ.AI, then to client
    });

    orRes.on('end', () => {
      const tail = rebrander.finish();
      if (tail.length) res.write(tail);
      res.end();
      const usage = extractor.finish();
      // Bill from what we observed. Content-free metadata only.
      reportSettlement({
        request_id: String(requestId),
        credit_id: billedCreditId,
        api_key_id: billedApiKeyId,
        model: usage.model || model,
        input_tokens: usage.inputTokens,
        output_tokens: usage.outputTokens,
        total_cost_usd: usage.totalCost,
        cost_source: 'stream',
        generation_id: usage.generationId,
        query_source: querySource,
        cache_read_tokens: usage.cacheReadTokens,
        cache_write_tokens: usage.cacheWriteTokens,
        is_online: Boolean(payload.plugins?.some?.((p) => p.id === 'web')),
        is_free_model: isFreeModel,
      });
    });

    orRes.on('error', (e) => {
      log(`upstream stream error: ${e.message}`);
      if (!res.writableEnded) res.end();
    });
  });

  upstream.on('error', (e) => {
    log(`openrouter connect error: ${e.message}`);
    if (!res.headersSent) {
      sendJson(res, 502, {
        error: { message: 'upstream unreachable', code: 502 },
      });
    } else if (!res.writableEnded) {
      res.end();
    }
  });

  upstream.write(orPayload);
  upstream.end();
}

/**
 * GET /attestation?nonce=<hex> — return a fresh NSM attestation document that
 * (a) proves this is a genuine Nitro enclave running image PCR0=…, (b) echoes
 * the client's nonce for freshness, and (c) commits to this enclave's TLS key
 * (public_key = SHA-256 of the cert SPKI). The document is self-authenticating
 * (AWS-signed), so it can be fetched over the untrusted channel.
 */
async function handleAttestation(req, res) {
  const q = new URL(req.url, 'http://x').searchParams;
  const nonceHex = sanitizeNonceHex(q.get('nonce') || '');
  const args = ['--public-key', CERT_SPKI_SHA256_HEX];
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

function start() {
  if (!OPENROUTER_API_KEY) {
    log('WARNING: OPENROUTER_API_KEY not set — chat calls will 401 upstream');
  }
  const certPem = readFileSync(cfg.tlsCertPath);
  // Fingerprint the cert's public key (SPKI) so the attestation doc can bind to
  // it and clients can pin the TLS endpoint to the attested enclave.
  const spkiDer = new X509Certificate(certPem).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  CERT_SPKI_SHA256_HEX = createHash('sha256').update(spkiDer).digest('hex');
  log(`TLS cert SPKI SHA-256: ${CERT_SPKI_SHA256_HEX}`);

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

start();
