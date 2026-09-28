// A decisions answer the enclave cannot seal back to the client: the upstream
// has already answered and billed, so the request still settles — and the
// settle, not an error report, says how it failed (`response_seal_failed`).
//
// The failure is injected into a real server process by preloading
// fixtures/response-seal-fails.mjs; the request is sealed with the real `ehbp`
// client to the key the server announces, so it is opened for real.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';
import { Identity } from 'ehbp';

const CREDIT = '00000000-0000-4000-8000-000000000001';

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
  const dir = mkdtempSync(join(tmpdir(), 'report-seal-'));
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
  const or = https.createServer(tls, async (req, res) => {
    await readBody(req);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 'gen-d', answers: {}, usage: { prompt_tokens: 3, completion_tokens: 1, cost: 0.0001 } }));
  });

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  await Promise.all([listen(hp, hpPort), listen(or, orPort)]);

  const preload = fileURLToPath(new URL('./fixtures/response-seal-fails.mjs', import.meta.url));
  const child = spawn(process.execPath, ['--import', preload, fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
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
  env.hpkePublicKeyHex = logs.text.match(/EHBP HPKE public key: ([0-9a-f]{64})/)?.[1];
  assert.ok(env.hpkePublicKeyHex, 'the server announces its HPKE public key');
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

function post(id, headers, payload) {
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path: '/v1/decisions', method: 'POST',
      rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-credit-id': CREDIT, 'x-query-source': 'api', 'x-request-id': id, ...headers,
      },
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject);
    r.end(payload);
  });
}

/** A decisions request HPKE-sealed with the real browser client. */
async function sealedDecisions(id, model) {
  const identity = await Identity.fromPublicKeyHex(env.hpkePublicKeyHex);
  const { request } = await identity.encryptRequestWithContext(
    new Request('https://enclave.test/v1/decisions', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: decisionsBody(model),
    }),
  );
  const encapKey = request.headers.get('Ehbp-Encapsulated-Key');
  return post(id, { 'ehbp-encapsulated-key': encapKey }, Buffer.from(await request.arrayBuffer()));
}

const settleFor = (id) => waitFor(() => env.settles.find((s) => s.request_id === id), `the settle for ${id}`);
const reportsFor = (id) => env.errors.filter((e) => e.trace?.client_request_id === id);

test('decisions: an answer that cannot be sealed back still settles, with response_seal_failed', { skip: SKIP }, async () => {
  const id = 'seal-fails-1';
  assert.equal(await sealedDecisions(id, 'd/ok'), 502);
  const settle = await settleFor(id);
  assert.equal(settle.failure_code, 'response_seal_failed', 'the settle says how it failed');
  assert.equal(settle.credit_id, CREDIT);
  await sleep(300);
  assert.deepEqual(reportsFor(id), [], 'a seal failure travels on the settle only, never as a (final) error report');
});

test('decisions: the same server settles an unsealed request with no failure_code', { skip: SKIP }, async () => {
  const id = 'seal-control-1';
  assert.equal(await post(id, {}, Buffer.from(decisionsBody('d/ok'))), 200);
  assert.equal('failure_code' in (await settleFor(id)), false);
  await sleep(150);
  assert.deepEqual(reportsFor(id), []);
});
