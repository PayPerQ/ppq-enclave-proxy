// A direct-only model (`venice/*`) must never fall through to OpenRouter.
//
// When its one upstream is skipped or fails, the candidate loop used to move
// on to OpenRouter, which has never heard of a `venice/*` id and answered
// "venice/… is not a valid model ID" — about a model that exists, for a
// request that failed for some other reason. The enclave now answers for what
// actually happened (directOnly.mjs).
//
// This drives the real server against a fake hp, a fake Venice and a fake
// OpenRouter, because the claim worth pinning is behavioural: OpenRouter is
// NOT CALLED. A unit test of the classifier cannot show that.
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

const VENICE = 'venice/venice-uncensored-1-2';
const veniceCandidate = {
  provider: 'venice', api_style: 'openai', host: 'api.venice.ai', path: '/api/v1/chat/completions',
  key_ref: 'venice', upstream_model: 'venice-uncensored-1-2', or_slug: VENICE,
  supports_tools: false, supports_image_input: true, max_images_per_message: 1,
};

/** Fake horse-power: authorizes everything with whatever candidate list the test set. */
function fakeHp(tls) {
  const state = { upstreams: [], errors: [], settles: [] };
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, upstreams: state.upstreams,
      }));
    }
    if (req.url === '/enclave/settle') { state.settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { state.errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, state };
}

/** A fake upstream that counts its calls and answers with a settable status. */
function fakeUpstream(tls, okBody) {
  const state = { status: 200, calls: 0 };
  const server = https.createServer(tls, async (req, res) => {
    await readJson(req);
    state.calls += 1;
    res.writeHead(state.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(state.status >= 400 ? { error: { message: 'upstream said no', code: state.status } } : okBody));
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

const img = { type: 'image_url', image_url: { url: `data:image/png;base64,${'A'.repeat(64)}` } };
const hi = [{ role: 'user', content: 'hi' }];

test('a direct-only model is answered by the enclave, never handed to OpenRouter', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'direct-only-refusal-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  // One certificate for every fake: the enclave reaches Venice by its real
  // name through the tunnel, so that name has to be on it too.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.venice.ai',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort, venicePort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeUpstream(tls, {
    id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'from openrouter' } }],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
  });
  const venice = fakeUpstream(tls, {
    id: 'v-1', object: 'chat.completion', model: 'venice-uncensored-1-2',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'from venice' } }],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
  });
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort), listen(venice.server, venicePort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      VENICE_PORT: String(venicePort), VENICE_API_KEY: 'venice-test-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  const withVenice = [veniceCandidate, { provider: 'openrouter' }];
  const refusedBy = async (label, body, upstreams = withVenice) => {
    hp.state.upstreams = upstreams;
    const orBefore = or.state.calls;
    const r = await chat(inboundPort, body);
    assert.equal(or.state.calls, orBefore, `${label}: OpenRouter must not be called\n${r.text}`);
    assert.doesNotMatch(r.text, /not a valid model ID/, label);
    assert.doesNotMatch(r.text.replaceAll(VENICE, ''), /venice|openrouter/i, `${label}: no upstream is named: ${r.text}`);
    return r;
  };

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // Control: a Venice request the upstream serves is served.
    hp.state.upstreams = withVenice;
    venice.state.status = 200;
    const served = await chat(inboundPort, { model: VENICE, messages: hi });
    assert.equal(served.status, 200, served.text);
    assert.equal(served.json.choices[0].message.content, 'from venice');

    // The request asks for something the model cannot do: 400, naming it.
    const veniceBefore = venice.state.calls;
    const tooMany = await refusedBy('two images on a one-image row', {
      model: VENICE, messages: [{ role: 'user', content: [{ type: 'text', text: 'look' }, img, img] }],
    });
    assert.equal(tooMany.status, 400);
    assert.deepEqual(tooMany.json, { error: {
      message: `The model "${VENICE}" accepts at most 1 image per message. Send fewer images in one message and retry.`,
      type: 'invalid_request_error', code: 'direct_only_model_unsupported_request',
    } });
    assert.equal(tooMany.headers['retry-after'], undefined, 'a 400 is not worth retrying');

    const bias = await refusedBy('logit_bias', { model: VENICE, messages: hi, logit_bias: { 50256: -100 } });
    assert.equal(bias.status, 400);
    assert.equal(bias.json.error.message, `The request field "logit_bias" is not supported by the model "${VENICE}". Remove it and retry.`);

    const heic = await refusedBy('heic image', {
      model: VENICE,
      messages: [{ role: 'user', content: [{ type: 'text', text: 'look' }, { type: 'image_url', image_url: { url: `data:image/heic;base64,${'A'.repeat(64)}` } }] }],
    });
    assert.equal(heic.status, 400);
    assert.match(heic.json.error.message, /PNG, JPEG or WebP images sent as base64 data URLs/);
    assert.equal(venice.state.calls, veniceBefore, 'a refused request never leaves for the upstream either');
    // The caller's own mistake is not an incident.
    assert.equal(hp.state.errors.length, 0, `a 400 refusal is not reported: ${JSON.stringify(hp.state.errors)}`);

    // The attempt was made and the upstream said no.
    venice.state.status = 429;
    const limited = await refusedBy('upstream 429', { model: VENICE, messages: hi });
    assert.equal(limited.status, 429);
    assert.equal(limited.json.error.code, 'direct_only_model_rate_limited');
    assert.equal(limited.headers['retry-after'], '5');

    venice.state.status = 500;
    const down = await refusedBy('upstream 500', { model: VENICE, messages: hi });
    assert.equal(down.status, 503);
    assert.equal(down.json.error.code, 'direct_only_model_unavailable');
    assert.equal(down.headers['retry-after'], '5');

    venice.state.status = 400;
    const drift = await refusedBy('upstream 400', { model: VENICE, messages: hi });
    assert.equal(drift.status, 502);
    assert.equal(drift.json.error.code, 'direct_only_model_upstream_error');
    assert.doesNotMatch(drift.text, /upstream said no/, 'the upstream body is not relayed');
    await waitFor(() => hp.state.errors.length >= 3, `the three upstream failures to be reported\n${logs}`);
    assert.equal(hp.state.errors.every((e) => e.code === 'upstream_unreachable' && e.provider === 'venice'), true, JSON.stringify(hp.state.errors));

    // hp offered no candidate that can serve it at all.
    venice.state.status = 200;
    const none = await refusedBy('no direct candidate', { model: VENICE, messages: hi }, [{ provider: 'openrouter' }]);
    assert.equal(none.status, 404);
    assert.equal(none.json.error.code, 'model_not_found');

    // Nothing was served in any refusal, so nothing was settled beyond the control.
    assert.equal(hp.state.settles.length, 1, `only the served request settles: ${hp.state.settles.length}`);

    // Control: every other model still falls back to OpenRouter as before.
    hp.state.upstreams = [{ provider: 'openrouter' }];
    const other = await chat(inboundPort, { model: 'openai/gpt-4.1-mini', messages: hi });
    assert.equal(other.status, 200, other.text);
    assert.equal(other.json.choices[0].message.content, 'from openrouter');
  } finally {
    child.kill('SIGKILL');
    for (const s of [hp.server, or.server, venice.server]) s.closeAllConnections?.();
    await Promise.all([hp.server, or.server, venice.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
