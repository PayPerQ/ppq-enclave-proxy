// The in-enclave /v1/audio/speech route (#397), driven end to end: the real
// server against a fake horse-power, a fake Deepgram, a fake ElevenLabs and a
// fake Tinfoil router that is a real EHBP recipient behind a fake ATC (the
// SEV-SNP/Sigstore verifier is swapped, fixtures/fakeVerifierRegister.mjs).
// What is asserted is the privacy contract and the billing contract: the text
// reaches only the provider (sealed, for Voxtral), horse-power sees counts and
// ids, audio streams back as MP3 (sealed to an EHBP client), nothing settles
// before the first audio byte, and what was synthesized settles after it.
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
import { EhbpRecipient } from '../src/ehbp-server.mjs';
import { TINFOIL_CONFIG_REPO, TINFOIL_HOST } from '../src/tinfoil.mjs';
import { DEEPGRAM_HOST, ELEVENLABS_HOST, VOXTRAL_SAMPLE_RATE } from '../src/speech.mjs';

const CREDIT = '00000000-0000-4000-8000-000000000003';
const TEXT = 'Welcome aboard!\nThis answer was generated privately. Now it is read aloud.';
const CANARY = 'generated privately';
const MEASUREMENT = 'c3'.repeat(48);

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
const parse = (buf) => { try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { return {}; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A fake MP3: the sync word, then filler, in two writes so the relay sees a stream. */
const MP3 = Buffer.concat([Buffer.from([0xff, 0xfb, 0x90, 0x64]), Buffer.alloc(3000, 0x5a)]);
/** 0.3 s of a quiet 16-bit sine at 24 kHz: what the fake router "synthesizes". */
function pcm() {
  const n = Math.round(VOXTRAL_SAMPLE_RATE * 0.3);
  const buf = Buffer.alloc(n * 2);
  for (let i = 0; i < n; i++) buf.writeInt16LE(Math.round(Math.sin((2 * Math.PI * 220 * i) / VOXTRAL_SAMPLE_RATE) * 0.05 * 32767), i * 2);
  return buf;
}
const isMp3 = (buf) => buf.length >= 2 && buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0;

let env;

before(async () => {
  if (SKIP) return;
  const dir = mkdtempSync(join(tmpdir(), 'speech-route-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost',
    '-addext', `subjectAltName=DNS:localhost,DNS:${TINFOIL_HOST},DNS:atc.tinfoil.sh,DNS:${DEEPGRAM_HOST},DNS:${ELEVENLABS_HOST}`,
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  // Fake horse-power: the model picks the candidate. `hp.authorizeStatus`
  // refuses; `hp.candidates(model)` may be replaced per test.
  const hp = { authorizes: [], settles: [], errors: [], authorizeStatus: 200 };
  const candidateFor = (model) => {
    if (model === 'tinfoil-voxtral-tts') {
      return [{ provider: 'tinfoil', api_style: 'speech', host: TINFOIL_HOST, path: '/v1/audio/speech', key_ref: 'tinfoil', upstream_model: 'voxtral-tts', voice: 'neutral_female', char_limit: 1200, or_slug: model }];
    }
    if (model === 'deepgram_aura_2') {
      return [{ provider: 'deepgram', api_style: 'speech', host: DEEPGRAM_HOST, path: '/v1/speak', key_ref: 'deepgram', upstream_model: 'aura-2-thalia-en', voice: 'aura-2-thalia-en', char_limit: 2000 }];
    }
    if (model === 'deepgram_tiny_chunks') {
      return [{ provider: 'deepgram', api_style: 'speech', host: DEEPGRAM_HOST, path: '/v1/speak', key_ref: 'deepgram', upstream_model: 'aura-2-thalia-en', voice: 'aura-2-thalia-en', char_limit: 30 }];
    }
    if (model === 'eleven_flash_v2_5') {
      return [{ provider: 'elevenlabs', api_style: 'speech', host: ELEVENLABS_HOST, path: '/v1/text-to-speech', key_ref: 'elevenlabs', upstream_model: model, voice: 'JBFqnCBsd6RMkjVDRZzb', char_limit: 5000, language: 'en', speed: 1.1 }];
    }
    return [];
  };
  hp.candidates = candidateFor;
  const hpServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    const body = parse(raw);
    if (req.url === '/enclave/authorize') {
      hp.authorizes.push({ body, raw: raw.toString('utf8'), headers: req.headers });
      if (hp.authorizeStatus !== 200) {
        res.writeHead(hp.authorizeStatus, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ authorized: false, error: { message: 'Insufficient credits.', type: 'insufficient_quota' } }));
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: CREDIT, api_key_id: 'key-under-test',
        resolved_model: body.model, is_free: false, upstreams: hp.candidates(body.model),
      }));
    }
    if (req.url === '/enclave/settle') { hp.settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { hp.errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });

  // Fake Deepgram: records the request; `deepgram.mode` = 'ok' | 'refuse' | 'empty' | 'hang'
  // (headers and one chunk, then held open until the client goes; `hangClosedAt` records when).
  const deepgram = { requests: [], mode: 'ok', hangClosedAt: 0 };
  const dgServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    deepgram.requests.push({ url: req.url, auth: req.headers.authorization, body: parse(raw) });
    if (deepgram.mode === 'refuse') {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ err_code: 'INVALID_VOICE', err_msg: 'voice not found' }));
    }
    if (deepgram.mode === 'empty') { res.writeHead(200, { 'content-type': 'audio/mpeg' }); return res.end(); }
    if (deepgram.mode === 'hang') {
      res.writeHead(200, { 'content-type': 'audio/mpeg' });
      res.write(MP3.subarray(0, 1000));
      req.socket.on('close', () => { deepgram.hangClosedAt = Date.now(); });
      return;
    }
    res.writeHead(200, { 'content-type': 'audio/mpeg' });
    res.write(MP3.subarray(0, 1000));
    await sleep(5);
    res.end(MP3.subarray(1000));
  });

  // Fake ElevenLabs.
  const eleven = { requests: [] };
  const elServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    eleven.requests.push({ url: req.url, key: req.headers['xi-api-key'], body: parse(raw) });
    res.writeHead(200, { 'content-type': 'audio/mpeg' });
    res.end(MP3);
  });

  // Fake Tinfoil router: an EHBP recipient. Records every request with its raw
  // bytes and whether it opened; answers sealed PCM in several frames.
  // `router.mode` = 'ok' | 'refuse' (a sealed 400) | 'unsealed' (a 2xx with no nonce).
  const recipient = await EhbpRecipient.generate();
  const router = { requests: [], mode: 'ok', publicKeyHex: await recipient.publicKeyHex() };
  const routerServer = https.createServer(tls, async (req, res) => {
    const raw = await readBody(req);
    const encap = req.headers['ehbp-encapsulated-key'];
    let opened = null;
    try { opened = typeof encap === 'string' ? await recipient.openRequest(encap, raw) : null; } catch { opened = null; }
    router.requests.push({ url: req.url, auth: req.headers.authorization, raw, sealed: Boolean(opened), body: opened ? parse(opened.plaintext) : null });
    if (!opened) { res.writeHead(400); return res.end('cannot open'); }
    if (router.mode === 'unsealed') { res.writeHead(200, { 'content-type': 'audio/pcm' }); return res.end(pcm()); }
    const enc = await recipient.responseEncryptor(opened.exportedSecret, opened.requestEnc);
    if (router.mode === 'refuse') {
      res.writeHead(400, { 'content-type': 'application/json', 'ehbp-response-nonce': enc.responseNonceHex });
      return res.end(await enc.encrypt(Buffer.from(JSON.stringify({ error: { message: 'voice not available', type: 'invalid_request_error' } }))));
    }
    res.writeHead(200, { 'content-type': 'audio/pcm', 'ehbp-response-nonce': enc.responseNonceHex });
    const audio = pcm();
    for (let i = 0; i < audio.length; i += 4001) {
      res.write(await enc.encrypt(audio.subarray(i, Math.min(i + 4001, audio.length))));
      await sleep(2);
    }
    res.end();
  });

  // Fake Tinfoil ATC: the router's attestation bundle, accepted by the fake
  // verifier when digest === measurement and repo is the router's config repo.
  const atc = { requests: [] };
  const atcServer = https.createServer(tls, async (req, res) => {
    atc.requests.push({ url: req.url, host: req.headers.host, body: parse(await readBody(req)) });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      domain: TINFOIL_HOST, digest: MEASUREMENT, vcek: 'VVVV', enclaveCert: 'CCCC', sigstoreBundle: {},
      enclaveAttestationReport: { format: 'fake', body: JSON.stringify({ repo: TINFOIL_CONFIG_REPO, measurement: MEASUREMENT, hpkePublicKey: router.publicKeyHex }) },
    }));
  });

  const [inboundPort, hpPort, orPort, dgPort, elPort, routerPort, atcPort] = await Promise.all(
    [freePort(), freePort(), freePort(), freePort(), freePort(), freePort(), freePort()],
  );
  const or = https.createServer(tls, (req, res) => { res.writeHead(404); res.end(); });
  await Promise.all([
    listen(hpServer, hpPort), listen(or, orPort), listen(dgServer, dgPort), listen(elServer, elPort),
    listen(routerServer, routerPort), listen(atcServer, atcPort),
  ]);

  const child = spawn(process.execPath, [
    '--import', fileURLToPath(new URL('./fixtures/fakeVerifierRegister.mjs', import.meta.url)),
    fileURLToPath(new URL('../src/server.mjs', import.meta.url)),
  ], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      TINFOIL_PORT: String(routerPort), TINFOIL_ATC_PORT: String(atcPort), TINFOIL_API_KEY: 'test-tinfoil-key',
      DEEPGRAM_PORT: String(dgPort), DEEPGRAM_API_KEY: 'test-deepgram-key',
      ELEVENLABS_PORT: String(elPort), ELEVENLABS_API_KEY: 'test-elevenlabs-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { text: '' };
  child.stdout.on('data', (d) => { logs.text += d; });
  child.stderr.on('data', (d) => { logs.text += d; });
  env = { dir, inboundPort, servers: [hpServer, or, dgServer, elServer, routerServer, atcServer], child, logs, hp, deepgram, eleven, router, atc };
  await waitFor(() => /listening \(TLS\)/.test(logs.text) || /worker \d listening/.test(logs.text), 'the server to listen');
  // The enclave's own HPKE key, as the boot log announces it (what /attestation commits to).
  env.hpkeHex = (await waitFor(() => /EHBP HPKE public key: ([0-9a-f]{64})/.exec(logs.text), 'the HPKE key'))[1];
});

after(async () => {
  if (!env) return;
  env.child.kill('SIGKILL');
  for (const s of env.servers) s.closeAllConnections?.();
  await Promise.all(env.servers.map((s) => new Promise((r) => s.close(r))));
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

/** POST /v1/audio/speech in the clear; resolves { status, headers, body }. `abortAfterMs` drops the connection that long after the first byte; resolves { aborted: true }. */
function post(id, body, { headers = {}, raw, abortAfterMs } = {}) {
  const payload = raw ?? Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port: env.inboundPort, path: '/v1/audio/speech', method: 'POST',
      rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': payload.length,
        'x-credit-id': CREDIT, 'x-query-source': 'ui', 'x-request-id': id, ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => {
        chunks.push(c);
        if (abortAfterMs && chunks.length === 1) setTimeout(() => { r.destroy(); resolve({ aborted: true, status: res.statusCode }); }, abortAfterMs);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', () => resolve({ aborted: true, status: res.statusCode }));
    });
    r.on('error', (e) => (abortAfterMs ? resolve({ aborted: true }) : reject(e)));
    r.end(payload);
  });
}

/** The same request sealed as the browser seals it (ehbp Identity); the answer unsealed the same way. */
async function postSealed(id, body) {
  const identity = await Identity.fromPublicKeyHex(env.hpkeHex);
  const { request: encReq, context } = await identity.encryptRequestWithContext(
    new Request('https://enclave.test/v1/audio/speech', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
  );
  const raw = Buffer.from(await encReq.arrayBuffer());
  const wire = await post(id, null, { raw, headers: { 'ehbp-encapsulated-key': encReq.headers.get('Ehbp-Encapsulated-Key') } });
  const nonce = wire.headers['ehbp-response-nonce'];
  if (!nonce) return { ...wire, sealed: false };
  const clear = await identity.decryptResponseWithContext(new Response(wire.body, { headers: { 'Ehbp-Response-Nonce': nonce } }), context);
  return { ...wire, sealed: true, wireBody: wire.body, body: Buffer.from(await clear.arrayBuffer()) };
}

const settleFor = (id) => waitFor(() => env.hp.settles.find((s) => s.request_id === id), `the settle for ${id}`);
const errorFor = (id, code) => waitFor(() => env.hp.errors.find((e) => e.trace?.client_request_id === id && (!code || e.code === code)), `the ${code ?? ''} report for ${id}`);

test('Deepgram: the text goes to the provider, counts go to horse-power, MP3 streams back and settles', { skip: SKIP }, async () => {
  const { status, headers, body } = await post('dg-1', { model: 'deepgram_aura_2', input: TEXT, tool_id: 'voice:thalia' });
  assert.equal(status, 200, `${body}\n${JSON.stringify(env.hp.errors.filter((e) => e.trace?.client_request_id === 'dg-1'))}\n${env.logs.text.slice(-1500)}`);
  assert.equal(headers['content-type'], 'audio/mpeg');
  assert.deepEqual(body, MP3, 'the provider bytes, relayed as they came');

  // horse-power saw counts and the resolution inputs, never the text.
  const auth = env.hp.authorizes.find((a) => a.headers['x-request-id'] === 'dg-1');
  assert.equal(auth.body.endpoint, 'speech');
  assert.equal(auth.body.input_chars, TEXT.length);
  assert.equal(auth.body.input_bytes, Buffer.byteLength(TEXT));
  assert.equal(auth.body.model, 'deepgram_aura_2');
  assert.equal(auth.raw.includes(CANARY), false, 'no text at authorize');
  assert.equal(auth.body.max_tokens, undefined);

  // The provider got the text as is, under the enclave's key, with the training opt-out.
  const sent = env.deepgram.requests.at(-1);
  assert.equal(sent.body.text, TEXT);
  assert.equal(sent.auth, 'Token test-deepgram-key');
  assert.match(sent.url, /^\/v1\/speak\?model=aura-2-thalia-en&encoding=mp3&mip_opt_out=true$/);

  const settle = await settleFor('dg-1');
  assert.equal(settle.endpoint, 'speech');
  assert.equal(settle.input_chars, TEXT.length);
  assert.equal(settle.chunk_count, 1);
  assert.equal(settle.provider, 'deepgram');
  assert.equal(settle.upstream_model, 'aura-2-thalia-en');
  assert.equal(settle.cost_source, 'speech-chars');
  assert.equal(settle.total_cost_usd, 0, 'hp prices; the enclave reports counts');
  assert.equal(settle.input_tokens, 0);
  assert.equal(settle.route, 'direct');
  assert.equal(settle.tool_id, 'voice:thalia');
  assert.equal(settle.query_source, 'ui');
  assert.equal(settle.failure_code, undefined);
  assert.equal(settle.trace.route.chosen, 'deepgram');
  assert.equal(settle.trace.route.api_style, 'speech');
  assert.equal(JSON.stringify(settle).includes(CANARY), false, 'no text at settle');
});

test('Voxtral: sealed to the attested router, single-line text, PCM levelled and encoded to MP3, settles under tinfoil', { skip: SKIP }, async () => {
  const { status, headers, body } = await post('tf-1', { model: 'tinfoil-voxtral-tts', input: TEXT });
  assert.equal(status, 200, env.logs.text.slice(-2000));
  assert.equal(headers['content-type'], 'audio/mpeg');
  assert.ok(isMp3(body), `MP3 out of PCM in, got ${body.subarray(0, 2).toString('hex')}`);
  assert.ok(body.length > 500, `audio of plausible size, got ${body.length}`);

  const sent = env.router.requests.at(-1);
  assert.equal(sent.sealed, true, 'the router could open it: sealed to its attested key');
  assert.equal(sent.raw.includes(Buffer.from(CANARY)), false, 'ciphertext on the wire to the router');
  assert.equal(sent.url, '/v1/audio/speech');
  assert.equal(sent.auth, 'Bearer test-tinfoil-key');
  assert.deepEqual(sent.body, {
    model: 'voxtral-tts', voice: 'neutral_female', response_format: 'pcm', stream_format: 'audio',
    // The line break after "!" becomes a space: the Voxtral form (horse-power #1185).
    input: 'Welcome aboard! This answer was generated privately. Now it is read aloud.',
  });
  assert.ok(env.atc.requests.length >= 1, 'the router was attested through ATC first');

  const settle = await settleFor('tf-1');
  assert.equal(settle.provider, 'tinfoil');
  assert.equal(settle.upstream_model, 'voxtral-tts');
  assert.equal(settle.input_chars, TEXT.length, "billed on the caller's characters, not the rewritten form");
  assert.equal(settle.chunk_count, 1);
  assert.equal(settle.endpoint, 'speech');
});

test('an EHBP client: the request is opened here, the MP3 goes back sealed, and nothing readable crosses the wire', { skip: SKIP }, async () => {
  const r = await postSealed('sealed-1', { model: 'eleven_flash_v2_5', input: TEXT });
  assert.equal(r.status, 200, `${r.body}\n${JSON.stringify(env.hp.errors.filter((e) => e.trace?.client_request_id === 'sealed-1'))}\n${env.logs.text.split('\n').filter((l) => /speech/.test(l)).join('\n')}`);
  assert.equal(r.sealed, true, 'Ehbp-Response-Nonce on the answer');
  assert.equal(r.headers['content-type'], 'audio/mpeg');
  assert.deepEqual(r.body, MP3, 'the client unseals the provider bytes');
  assert.equal(r.wireBody.equals(MP3), false, 'the wire carried ciphertext');
  // ElevenLabs got what hp resolved: model, voice path, language and speed.
  const sent = env.eleven.requests.at(-1);
  assert.match(sent.url, /^\/v1\/text-to-speech\/JBFqnCBsd6RMkjVDRZzb\/stream\?optimize_streaming_latency=3&output_format=mp3_44100_128$/);
  assert.equal(sent.key, 'test-elevenlabs-key');
  assert.equal(sent.body.text, TEXT);
  assert.equal(sent.body.model_id, 'eleven_flash_v2_5');
  assert.equal(sent.body.language_code, 'en');
  assert.equal(sent.body.voice_settings.speed, 1.1);
  const settle = await settleFor('sealed-1');
  assert.equal(settle.provider, 'elevenlabs');
  assert.equal(settle.trace.ehbp, true);
});

test('long text: chunked at the candidate limit, synthesized in order, one continuous MP3, counts cover the whole text', { skip: SKIP }, async () => {
  const before = env.deepgram.requests.length;
  const { status, body } = await post('chunks-1', { model: 'deepgram_tiny_chunks', input: TEXT });
  assert.equal(status, 200);
  const calls = env.deepgram.requests.slice(before);
  assert.ok(calls.length >= 3, `several chunks at a 30-char limit, got ${calls.length}`);
  assert.equal(calls.map((c) => c.body.text).join(' ').replace(/\s+/g, ' '), TEXT.replace(/\s+/g, ' '), 'every character went upstream, in order');
  for (const c of calls) assert.ok(c.body.text.length <= 30);
  assert.deepEqual(body, Buffer.concat(calls.map(() => MP3)), 'the chunks concatenated as one stream');
  const settle = await settleFor('chunks-1');
  assert.equal(settle.chunk_count, calls.length);
  assert.equal(settle.input_chars, TEXT.length);
});

test('a provider refusal before any audio is the client\'s answer with its status; nothing settles', { skip: SKIP }, async () => {
  env.deepgram.mode = 'refuse';
  try {
    const { status, headers, body } = await post('refuse-1', { model: 'deepgram_aura_2', input: TEXT });
    assert.equal(status, 400);
    assert.equal(headers['content-type'], 'application/json');
    assert.deepEqual(JSON.parse(body.toString()), { err_code: 'INVALID_VOICE', err_msg: 'voice not found' });
    const report = await errorFor('refuse-1', 'upstream_error_status');
    assert.equal(report.terminal, true);
    assert.equal(report.upstream_status, 400);
    assert.equal(report.provider, 'deepgram');
    await sleep(150);
    assert.equal(env.hp.settles.some((s) => s.request_id === 'refuse-1'), false, 'a refusal never settles');
  } finally {
    env.deepgram.mode = 'ok';
  }
});

test('a sealed refusal from the router is opened and relayed as JSON, never as ciphertext', { skip: SKIP }, async () => {
  env.router.mode = 'refuse';
  try {
    const { status, body } = await post('tf-refuse', { model: 'tinfoil-voxtral-tts', input: TEXT });
    assert.equal(status, 400);
    assert.deepEqual(JSON.parse(body.toString()), { error: { message: 'voice not available', type: 'invalid_request_error' } });
    await errorFor('tf-refuse', 'upstream_error_status');
  } finally {
    env.router.mode = 'ok';
  }
});

test('a 2xx the enclave cannot read (router answer without a nonce) is 502, final, unsettled', { skip: SKIP }, async () => {
  env.router.mode = 'unsealed';
  try {
    const { status, body } = await post('tf-unsealed', { model: 'tinfoil-voxtral-tts', input: TEXT });
    assert.equal(status, 502);
    assert.match(body.toString(), /unreadable/);
    const report = await errorFor('tf-unsealed', 'stream_failed');
    assert.equal(report.terminal, true);
    await sleep(150);
    assert.equal(env.hp.settles.some((s) => s.request_id === 'tf-unsealed'), false);
  } finally {
    env.router.mode = 'ok';
  }
});

test('a client hang-up mid-stream tears the provider down at once and settles the chunk that produced audio', { skip: SKIP }, async () => {
  env.deepgram.mode = 'hang';
  try {
    const t0 = Date.now();
    const r = await post('abort-1', { model: 'deepgram_aura_2', input: TEXT }, { abortAfterMs: 200 });
    assert.equal(r.aborted, true);
    assert.equal(r.status, 200, 'audio had started');
    const settle = await settleFor('abort-1');
    assert.ok(Date.now() - t0 < 5_000, 'settled promptly, not after the stream deadline');
    assert.equal(settle.chunk_count, 1);
    assert.equal(settle.input_chars, TEXT.length, 'one chunk was the whole text');
    assert.equal(settle.trace.stream_end, 'client_abort');
    await waitFor(() => env.deepgram.hangClosedAt > 0, 'the provider socket to be torn down');
    assert.equal(env.hp.errors.some((e) => e.trace?.client_request_id === 'abort-1' && e.code !== 'client_abort'), false, 'an abort is not a failure');
  } finally {
    env.deepgram.mode = 'ok';
  }
});

test('a 2xx with no audio at all is 502 and never billed', { skip: SKIP }, async () => {
  env.deepgram.mode = 'empty';
  try {
    const { status, body } = await post('empty-1', { model: 'deepgram_aura_2', input: TEXT });
    assert.equal(status, 502);
    assert.match(body.toString(), /no audio/);
    const report = await errorFor('empty-1', 'stream_failed');
    assert.equal(report.terminal, true);
    assert.equal(report.reason, 'NO_AUDIO');
    await sleep(150);
    assert.equal(env.hp.settles.some((s) => s.request_id === 'empty-1'), false);
  } finally {
    env.deepgram.mode = 'ok';
  }
});

test('horse-power\'s refusal passes through with its status and body; no provider is called', { skip: SKIP }, async () => {
  env.hp.authorizeStatus = 402;
  const before = env.deepgram.requests.length;
  try {
    const { status, body } = await post('auth-402', { model: 'deepgram_aura_2', input: TEXT });
    assert.equal(status, 402);
    assert.match(body.toString(), /Insufficient credits/);
    assert.equal(env.deepgram.requests.length, before);
    await errorFor('auth-402', 'authorize_rejected');
  } finally {
    env.hp.authorizeStatus = 200;
  }
});

test('no speech candidate from horse-power: refused 503 before any send, reported as unreachable', { skip: SKIP }, async () => {
  const { status, body } = await post('none-1', { model: 'eleven_v3_unknown', input: TEXT });
  assert.equal(status, 503);
  assert.match(body.toString(), /not available/);
  const report = await errorFor('none-1', 'upstream_unreachable');
  assert.equal(report.terminal, true);
  assert.equal(report.reason, 'NO_SPEECH_CANDIDATE');
});

test('a candidate whose provider, host and key disagree is refused, never sent', { skip: SKIP }, async () => {
  const prior = env.hp.candidates;
  env.hp.candidates = () => [{ provider: 'deepgram', api_style: 'speech', host: ELEVENLABS_HOST, path: '/v1/speak', key_ref: 'deepgram', upstream_model: 'v', voice: 'v', char_limit: 2000 }];
  const before = env.eleven.requests.length + env.deepgram.requests.length;
  try {
    const { status } = await post('bind-1', { model: 'deepgram_aura_2', input: TEXT });
    assert.equal(status, 503);
    const report = await errorFor('bind-1', 'upstream_unreachable');
    assert.equal(report.reason, 'PROVIDER_HOST_MISMATCH');
    assert.equal(env.eleven.requests.length + env.deepgram.requests.length, before);
  } finally {
    env.hp.candidates = prior;
  }
});

test('a malformed body is refused with a content-free 400 before authorize', { skip: SKIP }, async () => {
  const before = env.hp.authorizes.length;
  let r = await post('bad-1', { model: 'deepgram_aura_2' });
  assert.equal(r.status, 400);
  assert.equal(JSON.parse(r.body.toString()).error.param, 'input');
  r = await post('bad-2', { model: 'deepgram_aura_2', input: TEXT, voice: { $ne: 'x' } });
  assert.equal(r.status, 400);
  assert.equal(JSON.parse(r.body.toString()).error.param, 'voice');
  r = await post('bad-3', null, { raw: Buffer.from('{not json') });
  assert.equal(r.status, 400);
  assert.equal(env.hp.authorizes.length, before, 'nothing reached horse-power');
});

test('no credential: 401 before anything is read', { skip: SKIP }, async () => {
  const r = await post('anon-1', { model: 'deepgram_aura_2', input: TEXT }, { headers: { 'x-credit-id': '' } });
  assert.equal(r.status, 401);
});
