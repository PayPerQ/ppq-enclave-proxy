// Abliteration AI's failed answers, through the real server (horse-power #1371).
//
// A failed direct response is drained unread for every other provider. For
// this one the error envelope is read (directFailureBody.mjs), because its 403
// means two different things: its platform safety filter refused the caller's
// content (answered 400, nothing to retry, not an incident), or our own key
// lacks a permission (answered 503 and reported). The claim worth pinning is
// behavioural, so this drives the server against a fake hp, a fake provider
// and a fake OpenRouter that must never be called.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
const listen = (server, port) => new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
  });
}

const M = 'abliteration/abliterated-model-large-flash';
const candidate = {
  provider: 'abliteration', api_style: 'openai', host: 'api.abliteration.ai', path: '/v1/chat/completions',
  key_ref: 'abliteration', upstream_model: 'abliterated-model-large-flash', or_slug: M,
  supports_tools: true, supports_image_input: true, zdr: false,
};

function fakeHp(tls) {
  const state = { upstreams: [], errors: [], settles: [] };
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: state.upstreams, direct_only: null,
      }));
    }
    if (req.url === '/enclave/settle') { state.settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { state.errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, state };
}

/** A fake upstream whose status and raw error body the test sets; `hang` leaves the body open. */
function fakeUpstream(tls, okBody) {
  const state = { status: 200, errorBody: '{"error":{"message":"no","code":"x","type":"internal_error"}}', hang: false, calls: 0, lastBody: null, auth: null };
  const server = https.createServer(tls, async (req, res) => {
    state.lastBody = await readJson(req);
    state.auth = req.headers.authorization;
    state.calls += 1;
    res.writeHead(state.status, { 'content-type': 'application/json' });
    if (state.status < 400) return res.end(JSON.stringify(okBody));
    if (state.hang) return res.write(state.errorBody.slice(0, 5));
    res.end(state.errorBody);
  });
  return { server, state };
}

function chat(port, body) {
  const payload = JSON.stringify({ stream: false, ...body });
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-credit-id': '00000000-0000-4000-8000-000000000001', 'x-query-source': 'api',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
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

const hi = [{ role: 'user', content: 'hi' }];
const envelope = (code, type, message = 'said the provider') => JSON.stringify({ error: { code, type, message, param: null, request_id: 'req_1', doc_url: null } });

test('abliteration: the safety filter is a 400 to the caller, a permission 403 is an outage, OpenRouter is never asked', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'abliteration-refusal-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.abliteration.ai',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, ablPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeUpstream(tls, {
    id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'from openrouter' } }],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
  });
  const abl = fakeUpstream(tls, {
    id: 'chatcmpl-1', object: 'chat.completion', model: 'abliterated-model-large-flash',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'from abliteration' } }],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4, prompt_tokens_details: { cached_tokens: 0 } },
  });
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(abl.server, ablPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      ABLITERATION_PORT: String(ablPort), ABLITERATION_API_KEY: 'ak_test_key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  hp.state.upstreams = [candidate, { provider: 'openrouter' }];
  const failWith = async (label, status, errorBody, { hang = false } = {}) => {
    abl.state.status = status;
    abl.state.errorBody = errorBody;
    abl.state.hang = hang;
    const orBefore = or.state.calls;
    const ablBefore = abl.state.calls;
    const r = await chat(inboundPort, { model: M, messages: hi });
    assert.equal(abl.state.calls, ablBefore + 1, `${label}: the provider was tried`);
    assert.equal(or.state.calls, orBefore, `${label}: OpenRouter must not be called\n${r.text}`);
    assert.doesNotMatch(r.text.replaceAll(M, ''), /abliteration|openrouter|said the provider|req_1/i, `${label}: nothing of the upstream is relayed: ${r.text}`);
    return r;
  };

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // Control: served on its own tunnel, with its own key and the wire model.
    const served = await chat(inboundPort, { model: M, messages: hi, max_tokens: 9, max_completion_tokens: 7, tool_choice: 'auto' });
    assert.equal(served.status, 200, served.text);
    assert.equal(served.json.choices[0].message.content, 'from abliteration');
    assert.equal(abl.state.auth, 'Bearer ak_test_key');
    assert.equal(abl.state.lastBody.model, 'abliterated-model-large-flash');
    assert.equal(abl.state.lastBody.max_completion_tokens, 7);
    assert.equal(abl.state.lastBody.max_tokens, undefined);
    assert.equal(abl.state.lastBody.tool_choice, undefined);

    // Refused before it leaves: a field the provider rejects.
    const before = abl.state.calls;
    const minP = await chat(inboundPort, { model: M, messages: hi, min_p: 0.05 });
    assert.equal(minP.status, 400);
    assert.equal(minP.json.error.message, `The request field "min_p" is not supported by the model "${M}". Remove it and retry.`);
    assert.equal(abl.state.calls, before, 'a locally refused request never leaves');

    // The platform safety filter: the caller's content. 400, no retry hint,
    // and not an incident.
    const policy = await failWith('policy 403', 403, envelope('policy_violation', 'policy_error'));
    assert.equal(policy.status, 400, policy.text);
    assert.deepEqual(policy.json, { error: {
      message: `The request was declined by the safety policy that applies to the model "${M}". Change the request and retry.`,
      type: 'invalid_request_error', code: 'direct_only_model_unsupported_request',
    } });
    assert.equal(policy.headers['retry-after'], undefined);

    // A media error the local checks did not catch is the caller's image.
    const media = await failWith('media 422', 422, envelope('media_decode_failed', 'media_error'));
    assert.equal(media.status, 400, media.text);
    assert.match(media.json.error.message, /could not read an image/);
    // None of the three is an upstream failure, but each ended an authorized
    // request: one terminal `model_rejected` report apiece, which releases the
    // balance reservation hp took at authorize (#496).
    await waitFor(() => hp.state.errors.length >= 3, `the three 400 refusals to be reported\n${logs}`);
    assert.equal(hp.state.errors.length, 3, JSON.stringify(hp.state.errors));
    assert.equal(hp.state.errors.every((e) => e.code === 'model_rejected' && e.terminal === true && e.upstream_status === 400), true, JSON.stringify(hp.state.errors));
    const rejected = hp.state.errors.length;

    // A 403 that is NOT the filter is our key: an outage, retryable, reported.
    const permission = await failWith('permission 403', 403, envelope('permission_denied', 'permission_error'));
    assert.equal(permission.status, 503, permission.text);
    assert.equal(permission.json.error.code, 'direct_only_model_unavailable');
    assert.equal(permission.headers['retry-after'], '5');

    // A 403 whose body is not an envelope, or never finishes, is also ours:
    // the read is bounded, so the caller is answered rather than left waiting.
    const html = await failWith('non-JSON 403', 403, '<html>Access denied</html>');
    assert.equal(html.status, 503, html.text);
    const startedAt = Date.now();
    const hung = await failWith('403 with a body that never ends', 403, envelope('policy_violation', 'policy_error'), { hang: true });
    assert.equal(hung.status, 503, hung.text);
    assert.ok(Date.now() - startedAt < 10_000, 'the body read is bounded in time');

    // The statuses that already say what they are keep their meaning.
    const key = await failWith('rejected key', 401, envelope('invalid_api_key', 'auth_error'));
    assert.equal(key.status, 503);
    const limited = await failWith('rate limit', 429, envelope('rate_limit_exceeded', 'rate_limit_error'));
    assert.equal(limited.status, 429);
    const drift = await failWith('unsupported parameter', 400, envelope('unsupported_parameter', 'validation_error'));
    assert.equal(drift.status, 502);

    await waitFor(() => hp.state.errors.length >= rejected + 6, `the six upstream failures to be reported\n${logs}`);
    const failures = hp.state.errors.slice(rejected);
    assert.equal(failures.every((e) => e.code === 'upstream_unreachable' && e.provider === 'abliteration' && e.terminal === true), true, JSON.stringify(failures));
    assert.equal(failures.length, 6, JSON.stringify(failures.map((e) => e.upstream_status)));

    // Only the served control settled.
    assert.equal(hp.state.settles.length, 1, `only the served request settles: ${hp.state.settles.length}`);
  } finally {
    child.kill('SIGKILL');
    for (const s of [hp.server, or.server, abl.server]) s.closeAllConnections?.();
    await Promise.all([hp.server, or.server, abl.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
