// The receipt as a CLIENT receives it, from the real server against a fake hp
// and a fake OpenRouter. receipt.test.mjs pins the pieces; this pins what they
// add up to on the wire, which is where v1 went wrong without any piece being
// wrong: every receipt was well formed and correctly signed, and two requests
// for the same model still produced the same bytes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate, verify } from 'node:crypto';
import https from 'node:https';
import net from 'node:net';

import {
  RECEIPT_HEADER,
  RECEIPT_PREFIX,
  RECEIPT_SIG_HEADER,
  RECEIPT_SIG_PREFIX,
  RECEIPT_VERSION,
} from '../src/receipt.mjs';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
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

function fakeHp({ key, cert }) {
  return https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: [],
      }));
    }
    res.writeHead(200); res.end('{}');
  });
}

const SERVED = 'openai/gpt-4.1-mini-2025-04-14';

/**
 * Fake OpenRouter. A stream opens with a keep-alive comment, as the real one
 * does, and its first frame arrives in two writes split inside the line.
 */
function fakeOpenRouter({ key, cert }) {
  return https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (!body.stream) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        id: 'gen-1', object: 'chat.completion', model: SERVED,
        choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      }));
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const pause = () => new Promise((r) => setTimeout(r, 30));
    res.write(': OPENROUTER PROCESSING\n\n');
    await pause();
    res.write('data: {"id":"gen-2","mod');
    await pause();
    res.write(`el":"${SERVED}","choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n`);
    await pause();
    res.write(`data: {"id":"gen-2","model":"${SERVED}","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1}}\n\n`);
    res.end('data: [DONE]\n\n');
  });
}

function chat(port, { stream, requestId }) {
  const payload = JSON.stringify({ model: 'openai/gpt-4.1-mini', stream, messages: [{ role: 'user', content: 'hi' }] });
  const headers = {
    'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
    'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api',
  };
  if (requestId) headers['x-request-id'] = requestId;
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST',
      rejectUnauthorized: false, agent: false, headers,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.end(payload);
  });
}

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.fail(`timed out waiting for ${what}`);
}

/** The receipt of a stream: its JSON text, signature, and the index of each line. */
function receiptOfStream(text) {
  const lines = text.split('\n');
  const at = lines.findIndex((l) => l.startsWith(RECEIPT_PREFIX));
  const sigAt = lines.findIndex((l) => l.startsWith(RECEIPT_SIG_PREFIX));
  assert.notEqual(at, -1, `no receipt in the stream:\n${text}`);
  assert.notEqual(sigAt, -1, `no receipt signature in the stream:\n${text}`);
  return {
    json: lines[at].slice(RECEIPT_PREFIX.length),
    sig: JSON.parse(lines[sigAt].slice(RECEIPT_SIG_PREFIX.length)),
    at,
    firstFrameAt: lines.findIndex((l) => l.startsWith('data:')),
    lines,
  };
}

test('a client receives a receipt for ITS request, streamed or not', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'receipt-e2e-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  // What a verifier holds after the attestation check: the served key.
  const servedKey = new X509Certificate(tlsPair.cert).publicKey;
  const signedBy = (json, sig) =>
    verify('sha256', Buffer.from(json, 'utf8'), { key: servedKey, dsaEncoding: 'der' }, Buffer.from(sig.sig, 'base64'));

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair);
  const or = fakeOpenRouter(tlsPair);
  await Promise.all([listen(hp, hpPort), listen(or, orPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
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
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);
    const started = Date.now();

    // ── streamed ──────────────────────────────────────────────────────────
    const a = await chat(inboundPort, { stream: true, requestId: 'nonce-a' });
    assert.equal(a.status, 200);
    const ra = receiptOfStream(a.text);
    const receiptA = JSON.parse(ra.json);
    assert.equal(receiptA.v, RECEIPT_VERSION);
    assert.equal(receiptA.request_id, 'nonce-a');
    assert.equal(receiptA.request_id_source, 'client');
    assert.equal(receiptA.served_model, SERVED, 'the answer named its model before the receipt was written');
    assert.equal(receiptA.upstream, 'localhost');
    assert.ok(Math.abs(Date.parse(receiptA.issued_at) - started) < 60_000);
    assert.equal(signedBy(ra.json, ra.sig), true, 'signed by the key this connection was served');
    assert.ok(ra.at < ra.firstFrameAt, 'ahead of the first frame');
    assert.equal(ra.lines[0], ': PPQ.AI PROCESSING', 'the keep-alive comment passes first, rebranded');
    // Every frame still parses: the receipt did not land inside the split line.
    const frames = ra.lines.filter((l) => l.startsWith('data: {'));
    assert.equal(frames.length, 2);
    for (const f of frames) assert.doesNotThrow(() => JSON.parse(f.slice(6)), f);

    // ── the v1 defect: a second request for the same model ────────────────
    const b = await chat(inboundPort, { stream: true, requestId: 'nonce-b' });
    const rb = receiptOfStream(b.text);
    assert.notEqual(rb.json, ra.json);
    assert.equal(signedBy(ra.json, rb.sig), false, "one request's signature does not verify another's receipt");

    // ── no id from the caller: minted here, and said to be ────────────────
    const c = await chat(inboundPort, { stream: true });
    const receiptC = JSON.parse(receiptOfStream(c.text).json);
    assert.match(receiptC.request_id, /^enc-\d+-[a-z0-9]+$/);
    assert.equal(receiptC.request_id_source, 'enclave');

    // ── not streamed: the headers ─────────────────────────────────────────
    const d = await chat(inboundPort, { stream: false, requestId: 'nonce-d' });
    assert.equal(d.status, 200);
    assert.equal(JSON.parse(d.text).choices[0].message.content, 'ok', 'the body is untouched JSON');
    assert.equal(d.text.includes(RECEIPT_PREFIX.trim()), false);
    const json = Buffer.from(d.headers[RECEIPT_HEADER], 'base64').toString('utf8');
    const receiptD = JSON.parse(json);
    assert.equal(receiptD.request_id, 'nonce-d');
    assert.equal(receiptD.route, 'openrouter');
    assert.equal(receiptD.served_model, null, 'the headers leave before the answer arrives');
    assert.equal(signedBy(json, JSON.parse(d.headers[RECEIPT_SIG_HEADER])), true);
    assert.match(d.headers['access-control-expose-headers'], /Ppq-Routing-Receipt, Ppq-Routing-Receipt-Sig/);
  } finally {
    child.kill('SIGKILL');
    hp.closeAllConnections?.(); or.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.close(r)), new Promise((r) => or.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
