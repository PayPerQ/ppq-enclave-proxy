// Shared harness for the pii_redaction integration tests: the real server.mjs in
// a child process against a fake horse-power, a fake OpenRouter and a fake
// hosted PII detector, all over TLS with one throwaway certificate (the same
// shape as upstream-error-outcome.test.mjs). Fixtures are fictional.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

/** Fictional surfaces the fake detector finds, with their hosted labels. */
export const SURFACES = Object.freeze([
  ['Jane Roe', 'private_person'],
  ['jane.roe@example.com', 'private_email'],
]);

export function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
const parse = (buf) => { try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { return {}; } };

/** Code-point offsets of every SURFACES occurrence, as the hosted filter reports them. */
function hostedSpans(text) {
  const spans = [];
  for (const [surface, label] of SURFACES) {
    let from = 0;
    let i;
    while ((i = text.indexOf(surface, from)) !== -1) {
      const start = [...text.slice(0, i)].length;
      spans.push({ label, start, end: start + [...surface].length });
      from = i + surface.length;
    }
  }
  return spans;
}

export async function startPiiStack({ extraEnv = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'pii-stack-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const hp = { authorizes: [], settles: [], errors: [], authorizeStatus: 200 };
  const hpServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    const body = parse(raw);
    if (req.url === '/enclave/authorize') {
      hp.authorizes.push({ body, headers: req.headers });
      if (hp.authorizeStatus !== 200) {
        res.writeHead(hp.authorizeStatus, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ authorized: false, error: { message: 'insufficient balance', code: hp.authorizeStatus } }));
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: [],
      }));
    }
    if (req.url === '/enclave/settle') { hp.settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { hp.errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });

  // Fake OpenRouter: records raw bodies; answers with `or.respond(parsedBody)`
  // -> { status, contentType, body } where body is a string, or
  // `chunkBytes: n` to write it n bytes at a time (splitting UTF-8 sequences
  // and SSE events wherever they fall).
  const or = { requests: [], respond: null };
  const orServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    or.requests.push({ raw, body: parse(raw), headers: req.headers });
    const r = or.respond ? or.respond(parse(raw)) : { status: 200, contentType: 'application/json', body: '{}' };
    res.writeHead(r.status ?? 200, { 'content-type': r.contentType ?? 'application/json' });
    if (!r.chunkBytes) return res.end(r.body);
    const bytes = Buffer.from(r.body, 'utf8');
    for (let i = 0; i < bytes.length; i += r.chunkBytes) {
      res.write(bytes.subarray(i, i + r.chunkBytes));
      await new Promise((ok) => setTimeout(ok, 2));
    }
    res.end();
  });

  // Fake hosted detector: finds SURFACES; `detector.mode` = 'ok' | 'error' | 'unknown_label' | 'hang'.
  const detector = { requests: [], mode: 'ok' };
  const detServer = https.createServer(tls, async (req, res) => {
    const body = parse(await readBody(req));
    detector.requests.push({ body, url: req.url, auth: req.headers.authorization });
    if (detector.mode === 'hang') return;
    if (detector.mode === 'error') { res.writeHead(500); return res.end('boom'); }
    const spans = detector.mode === 'unknown_label'
      ? [{ label: 'something_new', start: 0, end: 1 }]
      : hostedSpans(String(body.text ?? ''));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ detected_spans: spans }));
  });

  const [inboundPort, hpPort, orPort, detPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  await Promise.all([
    new Promise((r) => hpServer.listen(hpPort, '127.0.0.1', r)),
    new Promise((r) => orServer.listen(orPort, '127.0.0.1', r)),
    new Promise((r) => detServer.listen(detPort, '127.0.0.1', r)),
  ]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      TINFOIL_API_KEY: 'test-tinfoil-key',
      PII_DETECTOR_HOST: 'localhost', PII_DETECTOR_PORT: String(detPort),
      NODE_EXTRA_CA_CERTS: certPath,
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stack = { hp, or, detector, inboundPort, logs: '' };
  child.stdout.on('data', (d) => { stack.logs += d; });
  child.stderr.on('data', (d) => { stack.logs += d; });

  stack.waitFor = async (predicate, what, ms = 15_000) => {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      const hit = predicate();
      if (hit) return hit;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error(`timed out waiting for ${what}\n${stack.logs}`);
  };
  await stack.waitFor(() => /listening \(TLS\)/.test(stack.logs) || /worker \d listening/.test(stack.logs), 'the server to listen');

  /** POST /v1/chat/completions with `body` (object or raw string); resolves { status, headers, text }. */
  stack.chat = (body, { requestId = `req-${Math.random().toString(36).slice(2)}` } = {}) => {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const r = https.request({
        host: '127.0.0.1', port: inboundPort, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
        headers: {
          'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
          'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api', 'x-request-id': requestId,
        },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), requestId }));
      });
      r.on('error', reject);
      r.end(payload);
    });
  };

  stack.stop = async () => {
    child.kill('SIGKILL');
    for (const s of [hpServer, orServer, detServer]) s.closeAllConnections?.();
    await Promise.all([hpServer, orServer, detServer].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  };
  return stack;
}
