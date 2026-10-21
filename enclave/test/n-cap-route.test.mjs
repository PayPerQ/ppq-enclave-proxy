// The spend cap on the chat path bounds `n` as well as max_tokens, and `n`
// travels to /enclave/authorize so hp can size the hold for every completion
// the body asks for (Oct 17-19 security reports: Malik Werkudhara).
//
// Drives the real server against a fake backend (answers every authorize with
// max_tokens_cap: 100 and records the bodies) and a fake OpenRouter that
// records the body it is sent, like online-suffix.test.mjs.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
const SKIP = !haveOpenssl() && 'openssl not available';
const CAP = 100;

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
function listen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
}
function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
  });
}

function fakeHp(tls) {
  const authorizes = [];
  const settles = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      authorizes.push({ body, requestId: req.headers['x-request-id'] });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, max_tokens_cap: CAP, upstreams: [],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, authorizes, settles };
}

function fakeOpenRouter(tls) {
  const seen = [];
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    seen.push({ body, requestId: JSON.stringify(body).match(/ncap-\d+/)?.[0] });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 'gen-c', object: 'chat.completion', model: body.model, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'OK' } }], usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4, cost: 0.0001 } }));
  });
  return { server, seen };
}

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'n-cap-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort)]);

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
  env = { dir, hp, or, child, logs, inboundPort };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of [env.hp.server, env.or.server]) s.closeAllConnections?.();
  await Promise.all([env.hp.server, env.or.server].map((s) => new Promise((r) => s.close(r))));
  rmSync(env.dir, { recursive: true, force: true });
});

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for ${what}\n${env?.logs.text ?? ''}`);
}

let seq = 0;
/** POST a chat body; resolves with hp's recorded authorize body, the upstream body and the settle. */
function chat(extra) {
  const id = `ncap-${++seq}`;
  const payload = Buffer.from(JSON.stringify({ model: 'openai/gpt-5.6-sol', messages: [{ role: 'user', content: id }], ...extra }));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-api-key': 'ppq-test-key', 'x-query-source': 'api', 'x-request-id': id,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      // The listener's own assertions and waits must fail THIS promise: an
      // async listener that throws only rejects its own promise, and the
      // caller would otherwise hang until the runner's timeout with no message.
      res.on('end', () => {
        (async () => {
          const text = Buffer.concat(chunks).toString('utf8');
          assert.equal(res.statusCode, 200, text);
          const authorize = await waitFor(() => env.hp.authorizes.find((a) => a.requestId === id), `the authorize for ${id}`);
          const sent = await waitFor(() => env.or.seen.find((s) => s.requestId === id), `the upstream body for ${id}`);
          const settle = await waitFor(() => env.hp.settles.find((s) => s.request_id === id), `the settle for ${id}`);
          return { authorize: authorize.body, sent: sent.body, settle };
        })().then(resolve, reject);
      });
    });
    r.on('error', reject);
    r.end(payload);
  });
}

test('n at the full cap: authorize learns n, the upstream gets one completion', { skip: SKIP }, async () => {
  const { authorize, sent, settle } = await chat({ max_tokens: 4000, n: 8 });
  assert.equal(authorize.n, 8, 'hp is told how many completions were asked for');
  assert.equal(authorize.max_tokens, 4000);
  assert.equal(sent.max_tokens, CAP);
  assert.equal(sent.n, 1, '8 * 100 would be 8x the cap; one completion fits');
  assert.equal(settle.trace.max_tokens_cap_applied, true);
  assert.equal(settle.trace.max_tokens_cap, CAP);
  assert.equal(settle.trace.max_tokens_cap_n, 1, 'the trace records the bound');
});

test('n within headroom: bounded to what fits, not to 1', { skip: SKIP }, async () => {
  const { sent, settle } = await chat({ max_tokens: 30, n: 8 });
  assert.equal(sent.max_tokens, 30);
  assert.equal(sent.n, 3);
  assert.equal(settle.trace.max_tokens_cap_n, 3);
});

test('n that already fits is forwarded untouched and the trace stays quiet', { skip: SKIP }, async () => {
  const { sent, settle } = await chat({ max_tokens: 20, n: 4 });
  assert.equal(sent.n, 4);
  assert.equal('max_tokens_cap_n' in settle.trace, false);
});

test('control: no n means no n anywhere (authorize body unchanged from before)', { skip: SKIP }, async () => {
  const { authorize, sent } = await chat({ max_tokens: 4000 });
  assert.equal('n' in authorize, false);
  assert.equal('n' in sent, false);
  assert.equal(sent.max_tokens, CAP);
});
