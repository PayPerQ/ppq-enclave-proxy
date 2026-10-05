// The terminal OpenRouter candidate is retried once on a 429 or a 503 before
// its status is passed through as the answer (server.mjs,
// RETRIED_UPSTREAM_STATUSES).
//
// Why: over Sep 17 – Oct 1 2026, 38 web requests from 30 users got an
// OpenRouter 429/503 relayed by the enclave. The old client-side fallback
// re-sent those in the clear and usually got a different provider; since
// PPQdotAI #2824 nothing leaves the enclave, so the retry has to live here.
//
// Drives the real server against a fake hp and a fake OpenRouter, like
// upstream-error-outcome.test.mjs, and asserts what the CLIENT gets, how many
// times OpenRouter was asked, and what hp receives: the served settle must
// name the first attempt beside the served one, and a request that recovered
// must not be reported as an upstream error.
import { test } from 'node:test';
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

/** Fake horse-power on the settle tunnel: authorizes everything, records the rest. */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: [],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors };
}

/**
 * Fake OpenRouter: answers each request with the next scripted status (200
 * once the script runs out), and counts how many times it was asked.
 */
function fakeOpenRouter({ key, cert }) {
  let script = [];
  let asked = 0;
  const server = https.createServer({ key, cert }, async (req, res) => {
    await readJson(req);
    asked += 1;
    const next = script.shift() ?? { status: 200 };
    const headers = { 'content-type': 'application/json', ...(next.headers ?? {}) };
    res.writeHead(next.status, headers);
    res.end(JSON.stringify(
      next.status >= 400
        ? { error: { message: 'Provider returned error', code: next.status, metadata: { raw: 'rate limited' } } }
        : { id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
            choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 } },
    ));
  });
  return {
    server,
    /** Script the next answers; resets the ask counter. */
    answer(...next) { script = next; asked = 0; },
    asked: () => asked,
  };
}

function chat(port, requestId) {
  const payload = JSON.stringify({ model: 'openai/gpt-4.1-mini', stream: false, messages: [{ role: 'user', content: 'hi' }] });
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-credit-id': '00000000-0000-4000-8000-000000000001',
        'x-query-source': 'api', 'x-request-id': requestId,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
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

test('the terminal OpenRouter candidate is retried once on 429/503', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'upstream-retry-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair);
  const or = fakeOpenRouter(tlsPair);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort)]);

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

    // A 429 that clears on the retry: the client never sees it.
    or.answer({ status: 429 });
    const recovered = await chat(inboundPort, 'req-429-then-200');
    assert.equal(recovered.status, 200, `a 429 that clears on the retry is served: ${recovered.body}`);
    assert.equal(JSON.parse(recovered.body).choices[0].message.content, 'ok');
    assert.equal(or.asked(), 2, 'OpenRouter was asked exactly twice');
    const settle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-429-then-200'), `the settle\n${logs}`);
    assert.equal(settle.trace?.stream_end, 'clean', 'a recovered request is clean');
    assert.equal(settle.trace?.route?.chosen, 'openrouter');
    assert.deepEqual(
      settle.trace?.route?.failed, [{ provider: 'openrouter', status: 429, class: 'http_4xx' }],
      'the first attempt is on the trace beside the served one',
    );
    assert.equal(
      hp.errors.some((e) => e.trace?.client_request_id === 'req-429-then-200'), false,
      'a recovered request is not reported as an upstream error',
    );

    // A 503 twice: the second answer is passed through, once.
    or.answer({ status: 503 }, { status: 503 });
    const stuck = await chat(inboundPort, 'req-503-twice');
    assert.equal(stuck.status, 503, 'the second answer is the one passed through');
    assert.equal(or.asked(), 2, 'one retry, not more');
    const report = await waitFor(
      () => hp.errors.find((e) => e.trace?.client_request_id === 'req-503-twice'),
      `the 503 error report\n${logs}`,
    );
    assert.equal(report.code, 'upstream_error_status');
    assert.equal(report.upstream_status, 503);

    // A Retry-After longer than a user would wait: passed through at once.
    or.answer({ status: 429, headers: { 'retry-after': '30' } });
    const later = await chat(inboundPort, 'req-429-retry-after-30');
    assert.equal(later.status, 429);
    assert.equal(or.asked(), 1, 'no retry against a long Retry-After');
    assert.equal(JSON.parse(later.body).error.code, 429, 'the passed-through body is intact');

    // A short Retry-After is honoured.
    or.answer({ status: 503, headers: { 'retry-after': '1' } });
    const started = Date.now();
    const honoured = await chat(inboundPort, 'req-503-retry-after-1');
    assert.equal(honoured.status, 200);
    assert.equal(or.asked(), 2);
    assert.ok(Date.now() - started >= 1000, 'the retry waited the second the upstream asked for');

    // Control: a 404 is not a transient status and is never retried.
    or.answer({ status: 404 });
    const refused = await chat(inboundPort, 'req-404');
    assert.equal(refused.status, 404);
    assert.equal(or.asked(), 1, 'a 404 is passed through without a retry');
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); or.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => or.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
