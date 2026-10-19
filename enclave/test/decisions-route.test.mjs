// The in-enclave /v1/decisions route, driven end to end: the real server
// against a fake horse-power and a fake OpenRouter decisions endpoint. What is
// asserted is the error-body contract (Oct 17-19 security reports,
// riskydwi27): a refused answer reaches the client with the SAME sanitizing
// the chat path and the dialect relay apply — no OpenRouter org `user_id`, no
// serving sub-provider, no openrouter.ai link, no vendor name — while the
// message and code the client acts on survive, and a served answer is still
// the upstream's own bytes.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';
import { MAX_ERROR_BODY_BYTES, sanitizedErrorBodyBuffer } from '../src/upstreamErrorBody.mjs';


const CREDIT = '00000000-0000-4000-8000-000000000002';
const ORG = 'org_test00000000000000000000';

/** The body OpenRouter answers a bad model id with, as upstreamErrorBody.mjs documents it. */
const LEAKY_404 = {
  error: {
    message: 'No endpoints found that support the requested parameters. See https://openrouter.ai/docs',
    code: 404,
    metadata: { provider_name: 'Venice', raw: 'upstream said: bad param' },
  },
  user_id: ORG,
};
const SERVED = { id: 'gen-d', answers: { q: true }, usage: { prompt_tokens: 3, completion_tokens: 1, cost: 0.0001 } };

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
const SKIP = !haveOpenssl() && 'openssl not available';

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
const listen = (server, port) => new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
async function readJson(req) {
  try { return JSON.parse((await readBody(req)).toString('utf8') || '{}'); } catch { return {}; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'decisions-route-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const settles = [];
  const errors = [];
  const hp = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: CREDIT, api_key_id: 'key-under-test',
        resolved_model: body.model, is_free: false, upstreams: [],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  // The model id picks the answer: `d/leak` is refused with OpenRouter's
  // leaky 404, `d/huge` with an error body over the sanitizer's byte bound,
  // anything else is served.
  const or = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (body.model === 'd/leak') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(LEAKY_404));
    }
    if (body.model === 'd/huge') {
      res.writeHead(502, { 'content-type': 'text/html' });
      return res.end(`<html>${ORG}${'x'.repeat(MAX_ERROR_BODY_BYTES)}</html>`);
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(SERVED));
  });

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  await Promise.all([listen(hp, hpPort), listen(or, orPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { text: '' };
  child.stdout.on('data', (d) => { logs.text += d; });
  child.stderr.on('data', (d) => { logs.text += d; });
  env = { dir, inboundPort, hp, or, child, logs, settles, errors };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of [env.hp, env.or]) s.closeAllConnections?.();
  await Promise.all([env.hp, env.or].map((s) => new Promise((r) => s.close(r))));
  rmSync(env.dir, { recursive: true, force: true });
});

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await sleep(25);
  }
  assert.fail(`timed out waiting for ${what}\n${env?.logs.text ?? ''}`);
}

const decisionsBody = (model) =>
  JSON.stringify({ model, state: 's', questions: { q: { type: 'noul', instructions: 'i' } } });

/** POST /v1/decisions; resolves `{ status, headers, text }`. */
function post(id, model) {
  const payload = Buffer.from(decisionsBody(model));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path: '/v1/decisions', method: 'POST',
      rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-credit-id': CREDIT, 'x-query-source': 'api', 'x-request-id': id,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.end(payload);
  });
}

test('decisions: a refused answer is sanitized like the chat and dialect routes', { skip: SKIP }, async () => {
  const { status, headers, text } = await post('leak-1', 'd/leak');
  assert.equal(status, 404, 'the upstream status still passes through');
  assert.equal(headers['content-type'], 'application/json');
  const body = JSON.parse(text);
  // What the product hides behind "AI Provider" stays hidden.
  assert.equal('user_id' in body, false, 'the OpenRouter org id is gone');
  assert.equal('provider_name' in body.error.metadata, false, 'the serving sub-provider is gone');
  assert.doesNotMatch(text, /openrouter/i, 'no vendor name or link anywhere in the body');
  // What the client acts on survives.
  assert.equal(body.error.code, 404);
  assert.match(body.error.message, /^No endpoints found that support the requested parameters/);
  assert.equal(body.error.metadata.raw, 'upstream said: bad param', 'the provider diagnostic is kept');
  // Unchanged: a refused decisions request is reported, never settled.
  await waitFor(() => env.errors.find((e) => e.trace?.client_request_id === 'leak-1'), 'the error report');
  await sleep(150);
  assert.equal(env.settles.some((s) => s.request_id === 'leak-1'), false, 'nothing settles for a refusal');
});

test('decisions: an oversized error body is replaced by the generic one, as JSON', { skip: SKIP }, async () => {
  const { status, headers, text } = await post('huge-1', 'd/huge');
  assert.equal(status, 502);
  assert.equal(headers['content-type'], 'application/json', 'the generic body is JSON whatever the upstream page was');
  assert.deepEqual(JSON.parse(text), { error: { message: 'upstream error', code: 502 } });
  assert.doesNotMatch(text, new RegExp(ORG));
});

test('decisions: a served answer is still the upstream\'s own bytes', { skip: SKIP }, async () => {
  const { status, text } = await post('served-1', 'd/ok');
  assert.equal(status, 200);
  assert.equal(text, JSON.stringify(SERVED), 'byte-identical: the sanitizer runs on refusals only');
  const settle = await waitFor(() => env.settles.find((s) => s.request_id === 'served-1'), 'the settle');
  assert.equal(settle.total_cost_usd, 0.0001);
});

test('sanitizedErrorBodyBuffer: sanitizes, and falls back to the generic body on overflow or a throwing sanitizer', () => {
  const clean = sanitizedErrorBodyBuffer(Buffer.from(JSON.stringify(LEAKY_404)), 404);
  assert.equal(clean.replaced, false);
  const parsed = JSON.parse(clean.body.toString('utf8'));
  assert.equal('user_id' in parsed, false);
  assert.equal('provider_name' in parsed.error.metadata, false);
  assert.doesNotMatch(clean.body.toString('utf8'), /openrouter/i);

  const big = sanitizedErrorBodyBuffer(Buffer.alloc(MAX_ERROR_BODY_BYTES + 1, 0x61), 503);
  assert.equal(big.replaced, true);
  assert.deepEqual(JSON.parse(big.body.toString('utf8')), { error: { message: 'upstream error', code: 503 } });

  // The byte bound does not bound nesting: a deeply nested document parses
  // and then overflows the recursive wording pass (CodeRabbit on #245).
  const nested = Buffer.from('['.repeat(50_000) + ']'.repeat(50_000));
  const deep = sanitizedErrorBodyBuffer(nested, 500);
  assert.equal(deep.replaced, true);
  assert.deepEqual(JSON.parse(deep.body.toString('utf8')), { error: { message: 'upstream error', code: 500 } });
});
