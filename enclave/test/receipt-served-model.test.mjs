// The receipt's served_model on a translated DIRECT route is the upstream's
// own echo, not ours (Oct 17-19 security reports, Refangga AF: "receipt
// served_model is the enclave's echo on direct routes").
//
// Before: the receipt gate stamps served_model from the first frame that names
// a model. On a direct Anthropic candidate that frame is synthesized by
// MessagesToChatSse from the CONFIGURED upstream id, so the receipt said
// `claude-sonnet-4-6` whatever Anthropic actually served; only the settle,
// fed by the synthesized usage frame at message_stop, carried the real
// `message_start.model`. Receipt and settle could name different models and
// the receipt could not witness an upstream-side substitution.
//
// Drives the real server against a fake hp and a fake Anthropic that echoes a
// DATED model id, and reads the receipt out of the stream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

import { RECEIPT_PREFIX } from '../src/receipt.mjs';

const ECHO = 'claude-sonnet-4-6-20250514';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; }
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
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function fakeHp({ key, cert }, upstreams) {
  const settles = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams,
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles };
}

/** Fake Anthropic Messages: a complete stream whose message_start echoes a DATED id. */
function fakeAnthropic({ key, cert }) {
  const sse = (obj) => `event: ${obj.type}\ndata: ${JSON.stringify(obj)}\n\n`;
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    seen.push({ path: req.url, body: await readJson(req) });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(sse({ type: 'message_start', message: { id: 'msg_01', type: 'message', role: 'assistant', model: ECHO, usage: { input_tokens: 3, output_tokens: 1 } } }));
    res.write(sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }));
    res.write(sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } }));
    res.write(sse({ type: 'content_block_stop', index: 0 }));
    res.write(sse({ type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 1 } }));
    res.end(sse({ type: 'message_stop' }));
  });
  return { server, seen };
}

function chat(port, body) {
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
        'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api', 'x-request-id': 'req-direct-echo',
      },
    }, (res) => {
      let text = '';
      res.on('data', (d) => { text += d; });
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    r.on('error', reject);
    r.end(body);
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

test('on a direct Anthropic stream the receipt names the model the upstream echoed, as the settle does', { skip: !haveOpenssl() && 'openssl not available', timeout: 90_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'receipt-served-model-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  // One certificate for every fake: the enclave validates the Anthropic hop
  // against its real name, hp against SETTLE_HOST=localhost.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.anthropic.com',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, anthropicPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair, [{
    provider: 'anthropic', api_style: 'anthropic', key_ref: 'anthropic', host: 'api.anthropic.com',
    path: '/v1/messages', upstream_model: 'claude-sonnet-4-6', or_slug: 'anthropic/claude-sonnet-4.6',
  }]);
  const up = fakeAnthropic(tlsPair);
  await Promise.all([listen(hp.server, hpPort), listen(up.server, anthropicPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      ANTHROPIC_PORT: String(anthropicPort), ANTHROPIC_API_KEY: 'test-anthropic-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);
    const body = JSON.stringify({ model: 'anthropic/claude-sonnet-4.6', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    const { status, text } = await chat(inboundPort, body);
    assert.equal(status, 200, `served by the direct candidate\n${logs}`);
    assert.equal(up.seen.length, 1, 'the fake Anthropic served it');

    const receiptLine = text.split('\n').find((l) => l.startsWith(RECEIPT_PREFIX));
    assert.ok(receiptLine, `a receipt in the stream:\n${text}`);
    const receipt = JSON.parse(receiptLine.slice(RECEIPT_PREFIX.length));
    assert.equal(receipt.served_model, ECHO, "the receipt carries the upstream's own echo, not our configured id");

    // The client-visible content frames are untouched: public slug, never the
    // bare wire id. (The trailing usage frame already carried the echo before
    // this change and still does; it is the settle's input, not this PR's.)
    const frames = text.split('\n').filter((l) => l.startsWith('data: ') && l !== 'data: [DONE]').map((l) => JSON.parse(l.slice(6)));
    const content = frames.filter((f) => f.choices?.length > 0);
    assert.ok(content.length >= 2, `content frames in the stream:\n${text}`);
    for (const f of content) assert.equal(f.model, 'anthropic/claude-sonnet-4.6');
    assert.ok(!text.includes('"model":"claude-sonnet-4-6"'), 'no bare wire id reaches the client');

    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-direct-echo'), `the settle\n${logs}`);
    assert.equal(settle.served_model, ECHO, 'receipt and settle name the same model');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); up.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => up.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
