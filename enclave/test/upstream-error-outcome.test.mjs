// An upstream 4xx is passed through to the client AND settled — so the settle
// is the only thing that tells hp what happened, and `trace.stream_end` is the
// only field in it that names an outcome (hp services/telemetry/enclave.ts,
// `classifyOutcome`, switches on nothing else).
//
// It used to say `clean`. The 404 body streams to completion like any other,
// so `src.on('end')` named the outcome and the early `finalize` — an
// in-enclave counter that never crosses the settle — did not. hp therefore
// filed a request OpenRouter had REFUSED as a successful one. Proved live
// 2026-09-23 against a real OpenRouter 404: the error report carried
// `upstream_error_status` + `upstream_status: 404` while the settle for the
// same request said the stream ended cleanly.
//
// This drives the real server against a fake hp and a fake OpenRouter and
// asserts what hp RECEIVES, because that is the contract — the counter, the
// log line and the error report were all already correct while the one field
// hp reads was wrong. The 200 case runs in the same test as the control: it is
// what stops the fix from being "call everything an error".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
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

/** Fake OpenRouter: answers with whatever status the current request asks for. */
function fakeOpenRouter({ key, cert }) {
  let status = 200;
  const server = https.createServer({ key, cert }, async (req, res) => {
    await readJson(req);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(
      status >= 400
        ? { error: { message: 'This model is unavailable for free.', code: status } }
        : { id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
            choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok' } }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 } },
    ));
  });
  return { server, setStatus: (s) => { status = s; } };
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
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
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

test('an upstream 4xx settles as upstream_error, a 2xx as clean', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'upstream-error-outcome-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  // One certificate for both fakes and for the enclave's own inbound listener:
  // every hostname involved is addressed as `localhost` here.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const { readFileSync } = await import('node:fs');
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
      // The fakes present the throwaway certificate; the enclave validates
      // both tunnels for real, so it has to trust it.
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    or.setStatus(404);
    assert.equal(await chat(inboundPort, 'req-4xx'), 404, 'the upstream status is passed through');
    const failed = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-4xx'), `the 4xx settle\n${logs}`);
    assert.equal(
      failed.trace?.stream_end, 'upstream_error',
      'a refused request must not reach hp as a clean one — hp files `clean` as status ok',
    );
    // Correlated through the TRACE, not the top-level `request_id`: that field
    // carries only ids this enclave minted (errorReport.mjs:142), so a client's
    // own `x-request-id` reaches hp as `trace.client_request_id` and nowhere
    // else. Anything downstream that joins a report to a settle has to key on
    // the same field.
    const report = await waitFor(
      () => hp.errors.find((e) => e.trace?.client_request_id === 'req-4xx'),
      `the 4xx error report\n${logs}`,
    );
    assert.equal(report.code, 'upstream_error_status');
    assert.equal(report.upstream_status, 404, 'the settle and the report must agree about the same request');

    or.setStatus(200);
    assert.equal(await chat(inboundPort, 'req-2xx'), 200);
    const served = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-2xx'), `the 2xx settle\n${logs}`);
    assert.equal(served.trace?.stream_end, 'clean', 'a served request is still clean');
    assert.equal(
      hp.errors.some((e) => e.trace?.client_request_id === 'req-2xx'), false,
      'a served request reports no error',
    );
  } finally {
    child.kill('SIGKILL');
    hp.server.closeAllConnections?.(); or.server.closeAllConnections?.();
    await Promise.all([new Promise((r) => hp.server.close(r)), new Promise((r) => or.server.close(r))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
