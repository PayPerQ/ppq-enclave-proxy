// Routing receipts on the dialect relay (#517): /v1/messages and /v1/responses
// carry the receipt /v1/chat/completions carries, in the same two forms. The
// real server against a fake horse-power, a fake OpenRouter that speaks both
// dialects, and a fake Anthropic for the direct candidate.
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
import { RECEIPT_HEADER, RECEIPT_PREFIX, RECEIPT_SIG_HEADER, RECEIPT_VERSION } from '../src/receipt.mjs';
import { splitReceipt } from './receiptLines.mjs';

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

/** What the client sends, what hp resolves it to, what OpenRouter's answer names. */
const REQUESTED = 'openai/gpt-4.1-mini';
const RESOLVED = 'openai/gpt-4.1-mini-2025-04';
const SERVED = 'openai/gpt-4.1-mini-2025-04-14';
/** The direct candidate: hp's wire id, and the dated snapshot Anthropic echoes. */
const DIRECT_SLUG = 'anthropic/claude-opus-5.5';
const DIRECT_WIRE = 'claude-opus-5-5';
const DIRECT_ECHO = 'claude-opus-5-5-20260921';
/** A model the fake OpenRouter refuses, and one whose stream ends with no frame. */
const REFUSED = 'test/refused';
/** The same refusal, labelled as an event stream by the upstream. */
const REFUSED_SSE = 'test/refused-sse';
const EMPTY = 'test/empty';
/** A whole stream in one write, whose terminal event names a different model than its first. */
const ONE_CHUNK = 'test/one-chunk';
const TERMINAL_ECHO = 'openai/gpt-4.1-mini-other';

/** Fake horse-power: resolves the alias, offers an Anthropic candidate for the direct model only. */
function fakeHp({ key, cert }) {
  return https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      const direct = body.model === DIRECT_SLUG;
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model === REQUESTED ? RESOLVED : body.model,
        is_free: false, web_search: false, provider_directive: null,
        upstreams: direct
          ? [{ provider: 'anthropic', api_style: 'anthropic', host: 'api.anthropic.com', path: '/v1/messages', key_ref: 'anthropic',
              upstream_model: DIRECT_WIRE, or_slug: DIRECT_SLUG, supports_tools: true, supports_image_input: true, context_length: 1000000, tier: 'default' }]
          : [],
      }));
    }
    res.writeHead(200); res.end('{}');
  });
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const messageStart = (model) => ({ type: 'message_start', message: { id: 'gen-1790000000-m1', type: 'message', role: 'assistant', content: [], model, stop_reason: null, usage: { input_tokens: 12, output_tokens: 1 } } });
const MESSAGE_REST = [
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } },
  { type: 'content_block_stop', index: 0 },
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3, cost: 0.00021 } },
  { type: 'message_stop' },
];
const messageJson = (model) => ({ id: 'gen-1790000000-m2', type: 'message', role: 'assistant', model, content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 12, output_tokens: 3, cost: 0.00021 } });
const responseCreated = (model) => ({ type: 'response.created', sequence_number: 0, response: { id: 'gen-1790000000-r1', object: 'response', model, status: 'in_progress', usage: null } });
const responseRest = (model) => [
  { type: 'response.output_text.delta', output_index: 0, delta: 'OK' },
  { type: 'response.completed', response: { id: 'gen-1790000000-r1', object: 'response', model, status: 'completed', usage: { input_tokens: 9, output_tokens: 3, cost: 0.00011 } } },
];
const responseJson = (model) => ({ id: 'gen-1790000000-r2', object: 'response', model, status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'OK' }] }], usage: { input_tokens: 9, output_tokens: 3, cost: 0.00011 } });

/**
 * A stream as a real upstream opens one: a keep-alive comment, then the first
 * frame in two writes split inside its line, then the rest.
 */
async function streamOut(res, first, rest) {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  const pause = () => new Promise((r) => setTimeout(r, 30));
  res.write(': OPENROUTER PROCESSING\n\n');
  await pause();
  const frame = sse(first);
  const cut = frame.indexOf('"model"') + 4;
  res.write(frame.slice(0, cut));
  await pause();
  res.write(frame.slice(cut));
  await pause();
  res.end(rest.map(sse).join(''));
}

/** Fake OpenRouter: `/api/v1/messages` and `/api/v1/responses`, stream or JSON; records what it was sent. */
function fakeOpenRouter({ key, cert }) {
  const seen = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    seen.push({ path: req.url, body });
    if (body.model === REFUSED || body.model === REFUSED_SSE) {
      res.writeHead(429, { 'content-type': body.model === REFUSED_SSE ? 'text/event-stream' : 'application/json' });
      return res.end(JSON.stringify({ error: { message: 'rate limited', code: 429 } }));
    }
    if (body.model === EMPTY) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      return res.end();
    }
    const messages = req.url === '/api/v1/messages';
    if (!messages && req.url !== '/api/v1/responses') { res.writeHead(404); return res.end(); }
    if (body.model === ONE_CHUNK) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      return res.end([responseCreated(SERVED), ...responseRest(TERMINAL_ECHO)].map(sse).join(''));
    }
    if (!body.stream) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(messages ? messageJson(SERVED) : responseJson(SERVED)));
    }
    return messages
      ? streamOut(res, messageStart(SERVED), MESSAGE_REST)
      : streamOut(res, responseCreated(SERVED), responseRest(SERVED));
  });
  return { server, seen };
}

/** Fake Anthropic: the direct candidate's own `/v1/messages`, echoing its dated snapshot. */
function fakeAnthropic({ key, cert }) {
  return https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url !== '/v1/messages') { res.writeHead(404); return res.end(); }
    if (!body.stream) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(messageJson(DIRECT_ECHO)));
    }
    return streamOut(res, messageStart(DIRECT_ECHO), MESSAGE_REST);
  });
}

function post(port, path, body, requestId) {
  const payload = JSON.stringify(body);
  const headers = {
    'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
    'x-api-key': 'ppq-test-key', 'x-query-source': 'api',
  };
  if (requestId) headers['x-request-id'] = requestId;
  return new Promise((resolve, reject) => {
    const r = https.request({ host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, raw, ...splitReceipt(raw) });
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

const messagesReq = (model, extra = {}) => ({ model, max_tokens: 200, stream: true, messages: [{ role: 'user', content: 'Say OK.' }], ...extra });
const responsesReq = (model, extra = {}) => ({ model, input: 'Say OK.', stream: true, ...extra });

test('the dialect relay issues the chat path’s routing receipt on /v1/messages and /v1/responses', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'receipt-relay-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.anthropic.com',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  // What a verifier holds after the attestation check: the served key.
  const servedKey = new X509Certificate(tlsPair.cert).publicKey;
  const signedBy = (json, sig) =>
    verify('sha256', Buffer.from(json, 'utf8'), { key: servedKey, dsaEncoding: 'der' }, Buffer.from(sig.sig, 'base64'));
  /** The header form: the receipt JSON and its signature object. */
  const headerReceipt = (res) => {
    assert.ok(res.headers[RECEIPT_HEADER], `no receipt header:\n${JSON.stringify(res.headers)}`);
    return {
      json: Buffer.from(res.headers[RECEIPT_HEADER], 'base64').toString('utf8'),
      sig: JSON.parse(res.headers[RECEIPT_SIG_HEADER]),
    };
  };

  const [inboundPort, hpPort, orPort, anPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair);
  const or = fakeOpenRouter(tlsPair);
  const an = fakeAnthropic(tlsPair);
  await Promise.all([listen(hp, hpPort), listen(or.server, orPort), listen(an, anPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      ANTHROPIC_PORT: String(anPort), ANTHROPIC_API_KEY: 'anthropic-test-key',
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

    for (const { name, path, req, first, rest } of [
      { name: 'messages', path: '/v1/messages', req: messagesReq, first: messageStart(SERVED), rest: MESSAGE_REST },
      { name: 'responses', path: '/v1/responses', req: responsesReq, first: responseCreated(SERVED), rest: responseRest(SERVED) },
    ]) {
      // ── streamed, through OpenRouter ────────────────────────────────────
      const s = await post(inboundPort, path, req(REQUESTED), `nonce-${name}-s`);
      assert.equal(s.status, 200, `${name}: ${s.raw}\n${logs}`);
      assert.ok(s.receiptJson, `${name}: no receipt in the stream:\n${s.raw}`);
      const rs = JSON.parse(s.receiptJson);
      assert.equal(rs.v, RECEIPT_VERSION);
      assert.equal(rs.request_id, `nonce-${name}-s`);
      assert.equal(rs.request_id_source, 'client');
      assert.equal(rs.requested_model, REQUESTED, `${name}: the caller's string, not hp's`);
      assert.equal(rs.resolved_model, RESOLVED, `${name}: what hp resolved it to`);
      assert.equal(rs.upstream_model, RESOLVED, `${name}: what went on the OpenRouter wire`);
      assert.equal(or.seen.at(-1).body.model, RESOLVED);
      assert.equal(rs.served_model, SERVED, `${name}: the first frame named its model before the receipt was written`);
      assert.equal(rs.upstream, 'localhost');
      assert.equal(rs.route, 'openrouter');
      assert.equal(rs.provider, 'openrouter');
      assert.equal(rs.upstream_selects_provider, true);
      assert.equal(rs.upstream_status, 200);
      assert.equal(rs.served_status, 200);
      assert.ok(Math.abs(Date.parse(rs.issued_at) - started) < 60_000);
      assert.equal(signedBy(s.receiptJson, s.sig), true, `${name}: signed by the key this connection was served`);
      // Where it sits: behind the upstream's keep-alive comment, ahead of the
      // first frame, and not inside the line that arrived in two writes.
      const lines = s.raw.split('\n');
      assert.match(lines[0], /^: /, `${name}: the keep-alive comment passes first`);
      const receiptAt = lines.findIndex((l) => l.startsWith(RECEIPT_PREFIX));
      const firstFrameAt = lines.findIndex((l) => l.startsWith('data:'));
      assert.ok(receiptAt < firstFrameAt, `${name}: ahead of the first frame`);
      // The frames themselves are the upstream's, untouched.
      assert.equal(s.body.slice(s.body.indexOf('data:')), [first, ...rest].map(sse).join(''), `${name}: frames verbatim`);

      // ── a second request: its own receipt ───────────────────────────────
      const s2 = await post(inboundPort, path, req(REQUESTED), `nonce-${name}-s2`);
      assert.notEqual(s2.receiptJson, s.receiptJson);
      assert.equal(signedBy(s.receiptJson, s2.sig), false, `${name}: one request's signature does not verify another's receipt`);

      // ── no id from the caller: minted here, and said to be ──────────────
      const minted = JSON.parse((await post(inboundPort, path, req(REQUESTED))).receiptJson);
      assert.match(minted.request_id, /^enc-\d+-[a-z0-9]+$/);
      assert.equal(minted.request_id_source, 'enclave');

      // ── not streamed: the header form, the body untouched ───────────────
      const j = await post(inboundPort, path, req(REQUESTED, { stream: false }), `nonce-${name}-j`);
      assert.equal(j.status, 200, j.raw);
      assert.equal(j.receiptJson, null, `${name}: a JSON body carries no comment line`);
      assert.doesNotThrow(() => JSON.parse(j.raw), `${name}: the JSON body still parses`);
      const hj = headerReceipt(j);
      const rj = JSON.parse(hj.json);
      assert.equal(rj.request_id, `nonce-${name}-j`);
      assert.equal(rj.requested_model, REQUESTED);
      assert.equal(rj.resolved_model, RESOLVED);
      assert.equal(rj.upstream_model, RESOLVED);
      assert.equal(rj.served_model, null, `${name}: the headers leave before a pass-through body arrives`);
      assert.equal(rj.route, 'openrouter');
      assert.equal(signedBy(hj.json, hj.sig), true, `${name}: header receipt signed`);

      // ── refused upstream: the receipt names where it went and both statuses ─
      const refused = await post(inboundPort, path, req(REFUSED), `nonce-${name}-r`);
      assert.equal(refused.status, 429, refused.raw);
      const hr = headerReceipt(refused);
      const rr = JSON.parse(hr.json);
      assert.equal(rr.request_id, `nonce-${name}-r`);
      assert.equal(rr.upstream_status, 429);
      assert.equal(rr.served_status, 429);
      assert.equal(rr.served_model, null);
      assert.equal(signedBy(hr.json, hr.sig), true);
      // A refusal the upstream labelled as a stream is one document too: header form.
      const refusedSse = await post(inboundPort, path, req(REFUSED_SSE), `nonce-${name}-rs`);
      assert.equal(refusedSse.status, 429, refusedSse.raw);
      const hrs = headerReceipt(refusedSse);
      assert.equal(JSON.parse(hrs.json).request_id, `nonce-${name}-rs`);
      assert.equal(signedBy(hrs.json, hrs.sig), true);

      // ── a stream that ends with no frame: the receipt still goes out, ahead of the error frame ─
      const empty = await post(inboundPort, path, req(EMPTY), `nonce-${name}-e`);
      assert.equal(empty.status, 200, empty.raw);
      const re = JSON.parse(empty.receiptJson);
      assert.equal(re.request_id, `nonce-${name}-e`);
      assert.equal(re.served_model, null);
      assert.equal(signedBy(empty.receiptJson, empty.sig), true);
      assert.ok(empty.raw.indexOf(RECEIPT_PREFIX) < empty.raw.indexOf('event: error'), `${name}: ahead of the in-band error`);
    }

    // ── one chunk, two echoes: the receipt names the first, as it does when they arrive apart ─
    const one = await post(inboundPort, '/v1/responses', responsesReq(ONE_CHUNK), 'nonce-one-chunk');
    assert.equal(one.status, 200, one.raw);
    assert.equal(JSON.parse(one.receiptJson).served_model, SERVED, 'the first echo, not the terminal one');
    assert.equal(signedBy(one.receiptJson, one.sig), true);

    // ── a direct candidate on /v1/messages ──────────────────────────────────
    const d = await post(inboundPort, '/v1/messages', messagesReq(DIRECT_SLUG), 'nonce-direct');
    assert.equal(d.status, 200, `${d.raw}\n${logs}`);
    const rd = JSON.parse(d.receiptJson);
    assert.equal(rd.route, 'direct');
    assert.equal(rd.provider, 'anthropic');
    assert.equal(rd.upstream, 'api.anthropic.com', 'the hostname the enclave validated');
    assert.equal(rd.upstream_model, DIRECT_WIRE, 'the wire id, not the public slug');
    assert.equal(rd.served_model, DIRECT_ECHO, 'the upstream’s own echo, read ahead of the slug rewrite');
    assert.equal(rd.upstream_selects_provider, false);
    assert.equal(signedBy(d.receiptJson, d.sig), true);
    assert.match(d.body, new RegExp(`"model":"${DIRECT_SLUG}"`), 'the client still sees the public slug');
    assert.doesNotMatch(d.body, new RegExp(DIRECT_ECHO));

    const dj = await post(inboundPort, '/v1/messages', messagesReq(DIRECT_SLUG, { stream: false }), 'nonce-direct-j');
    assert.equal(dj.status, 200, dj.raw);
    const hdj = headerReceipt(dj);
    const rdj = JSON.parse(hdj.json);
    assert.equal(rdj.route, 'direct');
    assert.equal(rdj.upstream_model, DIRECT_WIRE);
    assert.equal(signedBy(hdj.json, hdj.sig), true);
  } finally {
    child.kill('SIGKILL');
    hp.close(); or.server.close(); an.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
