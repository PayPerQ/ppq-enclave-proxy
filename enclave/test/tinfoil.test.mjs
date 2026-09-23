// The Tinfoil (private/*) upstream, #210. Two things must hold beyond the
// usual "does it build the request": a private request must never gain an
// OpenRouter fallback, and the client half of EHBP written here must be
// byte-compatible with the recipient half in ehbp-server.mjs — which is the
// same wire format Tinfoil's router speaks (proved live against
// inference.tinfoil.sh with ehbp 0.2.0 before this landed). So the seal/open
// tests round-trip through EhbpRecipient rather than a hand-rolled fixture.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { PassThrough } from 'node:stream';
import { once } from 'node:events';

import { EhbpRecipient } from '../src/ehbp-server.mjs';
import { normalizeCandidates } from '../src/upstreams.mjs';
import {
  DEFAULT_PRIVATE_MODEL,
  KEY_CONFIG_MISMATCH_STATUS,
  TINFOIL_ATC_HOST,
  TINFOIL_PROVIDER,
  USAGE_METRICS_HEADER,
  buildTinfoilRequest,
  claimedPrivateModel,
  createBundleCache,
  createResponseOpener,
  createTinfoilAttestor,
  decryptedStream,
  fetchTinfoilBundle,
  hasTinfoilCandidate,
  isPrivateModel,
  parseUsageMetrics,
  privateCandidates,
  projectForTinfoil,
  querySourceOf,
  refusesMisroutedToTinfoil,
  refusesUnroutedPrivate,
  relayHeaders,
  relayResponseHeaders,
  routerModelId,
  sealForTinfoil,
  toolIdOf,
  usageMetricsOf,
  validateBundleShape,
  verifyTinfoilBundle,
} from '../src/tinfoil.mjs';

const CANDIDATE = {
  provider: 'tinfoil',
  api_style: 'openai',
  host: 'inference.tinfoil.sh',
  path: '/v1/chat/completions',
  key_ref: 'tinfoil',
  upstream_model: 'glm-5-3',
  or_slug: 'private/glm-5-3',
};
const PORTS = { 'inference.tinfoil.sh': 9456 };
const KEYS = { tinfoil: 'tk_test' };

// ─── usage line ─────────────────────────────────────────────────────────────

test('parseUsageMetrics reads the router line, cost included, and clamps the cached count', () => {
  const m = parseUsageMetrics(
    'prompt=3018,completion=5,total=3023,cached_prompt_tokens=2048,uncached_prompt_tokens=970,model=glm-5-3,cost_usd=0.00001815',
  );
  assert.deepEqual(m, {
    promptTokens: 3018,
    completionTokens: 5,
    totalTokens: 3023,
    cachedPromptTokens: 2048,
    model: 'glm-5-3',
    costUsd: 0.00001815,
  });
  // A cached count above prompt is clamped down (a subset by convention).
  assert.equal(parseUsageMetrics('prompt=10,completion=1,cached_prompt_tokens=50').cachedPromptTokens, 10);
  // A malformed cached value must NOT round down into a discount.
  assert.equal(parseUsageMetrics('prompt=10,completion=1,cached_prompt_tokens=12.5').cachedPromptTokens, undefined);
  assert.equal(parseUsageMetrics('prompt=10,completion=1,cached_prompt_tokens=12junk').cachedPromptTokens, undefined);
  // Total falls back to the sum; a non-slug model is dropped, not echoed.
  const noTotal = parseUsageMetrics('prompt=10,completion=1,model=has space');
  assert.equal(noTotal.totalTokens, 11);
  assert.equal(noTotal.model, undefined);
});

test('parseUsageMetrics refuses what it cannot bill from', () => {
  assert.equal(parseUsageMetrics('completion=1'), null);
  assert.equal(parseUsageMetrics('prompt=x,completion=1'), null);
  assert.equal(parseUsageMetrics(''), null);
  assert.equal(parseUsageMetrics(undefined), null);
  assert.equal(parseUsageMetrics('a'.repeat(600)), null);
  // Negative counts clamp to zero rather than becoming a credit.
  assert.equal(parseUsageMetrics('prompt=-5,completion=-1').promptTokens, 0);
});

test('usageMetricsOf prefers the header and falls back to the trailer', () => {
  assert.equal(usageMetricsOf({ headers: { [USAGE_METRICS_HEADER]: 'prompt=1,completion=1' }, trailers: {} }), 'prompt=1,completion=1');
  assert.equal(usageMetricsOf({ headers: {}, trailers: { [USAGE_METRICS_HEADER]: 'prompt=2,completion=2' } }), 'prompt=2,completion=2');
  assert.equal(usageMetricsOf({ headers: {}, trailers: {} }), undefined);
  assert.equal(usageMetricsOf(undefined), undefined);
});

// ─── never OpenRouter ───────────────────────────────────────────────────────

test('a private candidate list loses the OpenRouter terminal normalizeCandidates adds', () => {
  // hp sends exactly one candidate; the connector's normaliser appends OR.
  const normalized = normalizeCandidates([CANDIDATE]);
  assert.equal(normalized.length, 2);
  assert.equal(normalized[1].provider, 'openrouter');
  assert.equal(hasTinfoilCandidate(normalized), true);
  assert.deepEqual(privateCandidates(normalized), [CANDIDATE]);
  // Not a private list: untouched.
  const fw = normalizeCandidates([{ provider: 'fireworks' }]);
  assert.equal(hasTinfoilCandidate(fw), false);
  assert.deepEqual(privateCandidates([]), []);
  assert.deepEqual(privateCandidates(undefined), []);
});

test('a private request with no Tinfoil candidate is refused, never routed to OpenRouter', () => {
  // An older hp resolves private ids like any other and answers with the usual
  // OpenRouter list; the enclave must not take it.
  assert.equal(refusesUnroutedPrivate('private/kimi-k3', normalizeCandidates([])), true);
  assert.equal(refusesUnroutedPrivate('private/kimi-k3', normalizeCandidates([{ provider: 'fireworks' }])), true);
  assert.equal(refusesUnroutedPrivate('private/kimi-k3', normalizeCandidates([CANDIDATE])), false);
  // Not a private model: the rule does not apply.
  assert.equal(refusesUnroutedPrivate('moonshotai/kimi-k3', normalizeCandidates([])), false);
});

test('a Tinfoil candidate for a public model is refused (provider substitution)', () => {
  assert.equal(refusesMisroutedToTinfoil('moonshotai/kimi-k3', normalizeCandidates([CANDIDATE])), true);
  assert.equal(refusesMisroutedToTinfoil('private/glm-5-3', normalizeCandidates([CANDIDATE])), false);
  assert.equal(refusesMisroutedToTinfoil('moonshotai/kimi-k3', normalizeCandidates([{ provider: 'fireworks' }])), false);
});

test('model helpers', () => {
  assert.equal(isPrivateModel('private/kimi-k3'), true);
  assert.equal(isPrivateModel('moonshotai/kimi-k3'), false);
  assert.equal(isPrivateModel(undefined), false);
  assert.equal(routerModelId('private/kimi-k3'), 'kimi-k3');
  assert.equal(routerModelId('kimi-k3'), 'kimi-k3');
  assert.equal(TINFOIL_PROVIDER, 'tinfoil');
  assert.equal(KEY_CONFIG_MISMATCH_STATUS, 422);
});

// ─── body projection ────────────────────────────────────────────────────────

test('projectForTinfoil forwards the caller body verbatim minus OpenRouter/PPQ fields, model rewritten', () => {
  const body = projectForTinfoil(
    {
      model: 'private/glm-5-3',
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
      stream_options: { include_usage: true },
      web_search_options: {},
      reasoning: { effort: 'low' },
      temperature: 0.2,
      provider: { ignore: ['venice'] },
      plugins: [{ id: 'web' }],
      transforms: ['middle-out'],
      usage: { include: true },
      query_source: 'ui',
      credit_id: 'c',
      tool_id: 't',
      zdr: true,
      nothing: undefined,
    },
    'glm-5-3',
  );
  assert.deepEqual(body, {
    model: 'glm-5-3',
    messages: [{ role: 'user', content: 'hi' }],
    stream: true,
    stream_options: { include_usage: true },
    web_search_options: {},
    reasoning: { effort: 'low' },
    temperature: 0.2,
  });
});

// ─── seal / open, against the enclave's own recipient ───────────────────────

test('sealForTinfoil produces a request the ehbp recipient opens; the opener reads its reply', async () => {
  const recipient = await EhbpRecipient.generate();
  const pub = await recipient.publicKeyHex();
  const plaintext = Buffer.from(JSON.stringify({ model: 'glm-5-3', messages: [] }));

  const sealed = await sealForTinfoil(pub, plaintext);
  assert.match(sealed.encapHex, /^[0-9a-f]{64}$/);
  assert.equal(sealed.body.readUInt32BE(0), sealed.body.length - 4);
  const opened = await recipient.openRequest(sealed.encapHex, sealed.body);
  assert.equal(opened.plaintext.toString('utf8'), plaintext.toString('utf8'));
  // The recipient's exported secret must equal the sender's: response keys
  // derive from it on both sides.
  assert.equal(Buffer.from(opened.exportedSecret).toString('hex'), Buffer.from(sealed.exportedSecret).toString('hex'));

  const encryptor = await recipient.responseEncryptor(opened.exportedSecret, opened.requestEnc);
  const frames = [
    await encryptor.encrypt(Buffer.from('data: {"a":1}\n\n')),
    await encryptor.encrypt(Buffer.from('data: {"b":2}\n\n')),
    await encryptor.encrypt(Buffer.from('data: [DONE]\n\n')),
  ];
  const opener = await createResponseOpener({ ...sealed, responseNonceHex: encryptor.responseNonceHex });
  // Deliver the frames as arbitrary chunks: two frames glued, the third split
  // mid-length-prefix and mid-ciphertext. Every complete frame comes out in
  // order; nothing partial ever does.
  const all = Buffer.concat(frames);
  const cut1 = frames[0].length + frames[1].length + 2;
  const cut2 = cut1 + 5;
  const out = [];
  out.push(await opener.feed(all.subarray(0, cut1)));
  out.push(await opener.feed(all.subarray(cut1, cut2)));
  out.push(await opener.feed(all.subarray(cut2)));
  assert.equal(Buffer.concat(out).toString('utf8'), 'data: {"a":1}\n\ndata: {"b":2}\n\ndata: [DONE]\n\n');
  assert.equal(opener.frames(), 3);
  opener.finish();
});

test('the opener refuses a truncated reply and a bad nonce', async () => {
  const recipient = await EhbpRecipient.generate();
  const sealed = await sealForTinfoil(await recipient.publicKeyHex(), Buffer.from('{}'));
  const opened = await recipient.openRequest(sealed.encapHex, sealed.body);
  const encryptor = await recipient.responseEncryptor(opened.exportedSecret, opened.requestEnc);
  const frame = await encryptor.encrypt(Buffer.from('hello'));
  const opener = await createResponseOpener({ ...sealed, responseNonceHex: encryptor.responseNonceHex });
  await opener.feed(frame.subarray(0, frame.length - 3));
  assert.throws(() => opener.finish(), /truncated/);
  await assert.rejects(createResponseOpener({ ...sealed, responseNonceHex: 'zz' }), /malformed/);
  await assert.rejects(createResponseOpener({ ...sealed, responseNonceHex: 'ab' }), /nonce length/);
  // A frame sealed under a different response nonce does not open.
  const other = await createResponseOpener({ ...sealed, responseNonceHex: 'ff'.repeat(32) });
  await assert.rejects(other.feed(frame));
});

test('decryptedStream yields plaintext over a sealed upstream and errors on a bad frame', async () => {
  const recipient = await EhbpRecipient.generate();
  const sealed = await sealForTinfoil(await recipient.publicKeyHex(), Buffer.from('{}'));
  const opened = await recipient.openRequest(sealed.encapHex, sealed.body);
  const encryptor = await recipient.responseEncryptor(opened.exportedSecret, opened.requestEnc);
  const frames = [await encryptor.encrypt(Buffer.from('one')), await encryptor.encrypt(Buffer.from('two'))];

  const up = new PassThrough();
  const src = decryptedStream(up, await createResponseOpener({ ...sealed, responseNonceHex: encryptor.responseNonceHex }));
  const chunks = [];
  src.on('data', (c) => chunks.push(c));
  const ended = once(src, 'end');
  up.write(frames[0]);
  up.write(frames[1]);
  up.end();
  await ended;
  assert.equal(Buffer.concat(chunks).toString('utf8'), 'onetwo');

  const up2 = new PassThrough();
  const src2 = decryptedStream(up2, await createResponseOpener({ ...sealed, responseNonceHex: 'aa'.repeat(32) }));
  src2.on('data', () => {});
  const errored = once(src2, 'error');
  up2.write(frames[0]);
  const [err] = await errored;
  assert.ok(err);
  // The upstream is torn down, not left open and paused behind an unpiped stream.
  assert.equal(up2.destroyed, true);
});

// ─── request builders ───────────────────────────────────────────────────────

test('buildTinfoilRequest seals the projected body to the given key and addresses the tunnel', async () => {
  const recipient = await EhbpRecipient.generate();
  const pub = await recipient.publicKeyHex();
  const r = await buildTinfoilRequest({
    candidate: CANDIDATE,
    basePayload: { model: 'private/glm-5-3', messages: [{ role: 'user', content: 'hi' }], provider: { zdr: true } },
    ports: PORTS,
    keys: KEYS,
    hpkePublicKeyHex: pub,
  });
  assert.equal(r.skip, undefined);
  assert.equal(r.provider, 'tinfoil');
  assert.equal(r.apiStyle, 'tinfoil');
  assert.equal(r.orSlug, 'private/glm-5-3');
  assert.equal(r.upstreamModel, 'glm-5-3');
  assert.equal(r.opts.host, '127.0.0.1');
  assert.equal(r.opts.port, 9456);
  assert.equal(r.opts.servername, 'inference.tinfoil.sh');
  assert.equal(r.opts.path, '/v1/chat/completions');
  assert.equal(r.opts.headers.host, 'inference.tinfoil.sh');
  assert.equal(r.opts.headers.authorization, 'Bearer tk_test');
  assert.equal(r.opts.headers['x-tinfoil-request-usage-metrics'], 'true');
  assert.equal(r.opts.headers.te, 'trailers');
  assert.equal(r.opts.headers['content-length'], r.bodyStr.length);
  assert.ok(Buffer.isBuffer(r.bodyStr));
  // What went on the wire is the projected body, and only the recipient can read it.
  const opened = await recipient.openRequest(r.opts.headers['ehbp-encapsulated-key'], r.bodyStr);
  assert.deepEqual(JSON.parse(opened.plaintext.toString('utf8')), {
    model: 'glm-5-3',
    messages: [{ role: 'user', content: 'hi' }],
  });
  assert.ok(r.seal.exportedSecret instanceof Uint8Array);
  assert.ok(r.seal.requestEnc instanceof Uint8Array);
});

test('buildTinfoilRequest skips without a tunnel, a key, or a verified attestation', async () => {
  const base = { candidate: CANDIDATE, basePayload: { model: 'private/glm-5-3', messages: [] } };
  assert.equal((await buildTinfoilRequest({ ...base, ports: {}, keys: KEYS, hpkePublicKeyHex: 'ab'.repeat(32) })).skip, 'no_tunnel_or_key');
  assert.equal((await buildTinfoilRequest({ ...base, ports: PORTS, keys: {}, hpkePublicKeyHex: 'ab'.repeat(32) })).skip, 'no_tunnel_or_key');
  assert.equal((await buildTinfoilRequest({ ...base, ports: PORTS, keys: KEYS, hpkePublicKeyHex: null })).skip, 'tinfoil_attestation_failed');
});

test('relayHeaders forwards the seal and content type, and swaps the credential for ours', () => {
  const h = relayHeaders(
    {
      authorization: 'Bearer sk-user-ppq-key',
      'x-credit-id': 'c',
      'ehbp-encapsulated-key': 'aa'.repeat(32),
      'content-type': 'application/json; charset=utf-8',
      'x-private-model': 'private/kimi-k3',
    },
    { host: 'inference.tinfoil.sh', key: 'tk_test', bodyLength: 42 },
  );
  assert.deepEqual(h, {
    host: 'inference.tinfoil.sh',
    'content-type': 'application/json; charset=utf-8',
    'content-length': 42,
    authorization: 'Bearer tk_test',
    'x-tinfoil-request-usage-metrics': 'true',
    'ehbp-encapsulated-key': 'aa'.repeat(32),
    te: 'trailers',
  });
  // Nothing of the caller's credential or credit id reaches the router.
  assert.equal(JSON.stringify(h).includes('sk-user'), false);
  assert.equal('x-credit-id' in h, false);
  assert.equal(relayHeaders({}, { host: 'h', key: 'k', bodyLength: 0 })['content-type'], 'application/json');
});

test('relayResponseHeaders mirrors horse-power: header on JSON, trailer announced on a 200 stream', () => {
  const json = relayResponseHeaders({
    statusCode: 200,
    headers: { 'ehbp-response-nonce': 'ab', 'content-type': 'application/json', [USAGE_METRICS_HEADER]: 'prompt=1,completion=1' },
  });
  assert.deepEqual(json, {
    headers: { 'Ehbp-Response-Nonce': 'ab', 'Content-Type': 'application/json', 'X-Tinfoil-Usage-Metrics': 'prompt=1,completion=1' },
    streaming: false,
  });
  const stream = relayResponseHeaders({
    statusCode: 200,
    headers: { 'ehbp-response-nonce': 'cd', 'content-type': 'text/event-stream; charset=utf-8' },
  });
  assert.deepEqual(stream, {
    headers: { 'Ehbp-Response-Nonce': 'cd', 'Content-Type': 'text/event-stream; charset=utf-8', Trailer: 'X-Tinfoil-Usage-Metrics' },
    streaming: true,
  });
  // An error status announces no trailer and carries no nonce.
  const err = relayResponseHeaders({ statusCode: 422, headers: { 'content-type': 'application/problem+json' } });
  assert.deepEqual(err, { headers: { 'Content-Type': 'application/problem+json' }, streaming: false });
});

test('cleartext header readers', () => {
  assert.equal(claimedPrivateModel({ 'x-private-model': 'private/glm-5-3', 'x-tinfoil-model': 'private/kimi-k3' }), 'private/glm-5-3');
  assert.equal(claimedPrivateModel({ 'x-encrypted-model': 'private/gemma4-31b' }), 'private/gemma4-31b');
  assert.equal(claimedPrivateModel({}), DEFAULT_PRIVATE_MODEL);
  assert.equal(toolIdOf({ 'x-tool-id': 'stt:ppq-voice' }), 'stt:ppq-voice');
  assert.equal(toolIdOf({ 'x-tool-id': 'has space' }), null);
  assert.equal(toolIdOf({ 'x-tool-id': 'x'.repeat(65) }), null);
  assert.equal(toolIdOf({}), null);
  assert.equal(querySourceOf({ 'x-query-source': 'ui' }), 'ui');
  assert.equal(querySourceOf({ 'x-query-source': 'memory' }), 'memory');
  assert.equal(querySourceOf({ 'x-query-source': 'anything-else' }), 'api');
  assert.equal(querySourceOf({}), 'api');
});

// ─── attestation schedule ───────────────────────────────────────────────────

const BUNDLE = {
  domain: 'inference.tinfoil.sh',
  enclaveAttestationReport: { format: 'https://tinfoil.sh/predicate/sev-snp-guest/v2', body: 'AAAA' },
  digest: 'd'.repeat(64),
  sigstoreBundle: { mediaType: 'x' },
  vcek: 'BBBB',
  enclaveCert: 'CCCC',
};

test('validateBundleShape names the missing field', () => {
  assert.equal(validateBundleShape(BUNDLE), BUNDLE);
  assert.throws(() => validateBundleShape(null), /not an object/);
  assert.throws(() => validateBundleShape({ ...BUNDLE, vcek: '' }), /missing vcek/);
  assert.throws(() => validateBundleShape({ ...BUNDLE, enclaveAttestationReport: {} }), /enclaveAttestationReport/);
  assert.throws(() => validateBundleShape({ ...BUNDLE, sigstoreBundle: 'nope' }), /sigstoreBundle/);
});

test('verifyTinfoilBundle hands the verifier the bundle and returns only a well-formed key', async () => {
  const seen = [];
  const verifierImpl = () => ({
    async verifyBundle(b) {
      seen.push(b);
      return { hpkePublicKey: 'AB'.repeat(32), measurement: { registers: ['m'.repeat(96)] } };
    },
  });
  const v = await verifyTinfoilBundle(BUNDLE, { enclaveHost: 'inference.tinfoil.sh', verifierImpl });
  assert.equal(v.hpkePublicKeyHex, 'ab'.repeat(32));
  assert.equal(v.measurement, 'm'.repeat(96));
  assert.equal(v.domain, 'inference.tinfoil.sh');
  assert.deepEqual(Object.keys(seen[0]).sort(), ['digest', 'domain', 'enclaveAttestationReport', 'enclaveCert', 'sigstoreBundle', 'vcek']);
  // A bundle for a different router than the pin names is refused before verification.
  await assert.rejects(
    verifyTinfoilBundle({ ...BUNDLE, domain: 'other.tinfoil.sh' }, { enclaveHost: 'inference.tinfoil.sh', verifierImpl }),
    /expected inference.tinfoil.sh/,
  );
  // A verifier that returns no usable key is a failure, not an empty key.
  await assert.rejects(
    verifyTinfoilBundle(BUNDLE, { verifierImpl: () => ({ async verifyBundle() { return { hpkePublicKey: 'short' }; } }) }),
    /no 32-byte HPKE key/,
  );
  // The verifier's own rejection propagates.
  await assert.rejects(
    verifyTinfoilBundle(BUNDLE, { verifierImpl: () => ({ async verifyBundle() { throw new Error('measurement mismatch'); } }) }),
    /measurement mismatch/,
  );
});

test('fetchTinfoilBundle POSTs the pinned router to ATC over its tunnel', async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, host: req.headers.host, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(BUNDLE));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const bundle = await fetchTinfoilBundle({ atcPort: server.address().port, enclaveHost: 'inference.tinfoil.sh', requestImpl: http.request });
    assert.deepEqual(bundle, BUNDLE);
    assert.equal(seen[0].method, 'POST');
    assert.equal(seen[0].url, '/attestation');
    assert.equal(seen[0].host, TINFOIL_ATC_HOST);
    assert.deepEqual(JSON.parse(seen[0].body), { enclaveUrl: 'https://inference.tinfoil.sh' });
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});

test('the attestor fetches once per TTL, shares one in-flight fetch, and refetches after invalidate', async () => {
  let clock = 1_000_000;
  let fetches = 0;
  let verifies = 0;
  const attestor = createTinfoilAttestor({
    enclaveHost: 'inference.tinfoil.sh',
    atcPort: 9455,
    ttlMs: 1000,
    now: () => clock,
    fetchBundle: async () => {
      fetches += 1;
      await new Promise((r) => setTimeout(r, 5));
      return BUNDLE;
    },
    verify: async (b, { enclaveHost }) => {
      verifies += 1;
      assert.equal(enclaveHost, 'inference.tinfoil.sh');
      return { hpkePublicKeyHex: `${fetches}`.padStart(64, '0'), measurement: 'm', domain: b.domain };
    },
  });
  assert.deepEqual(attestor.state(), { configured: true, verified: false, verified_at: null, measurement: null, last_error: null });
  // Two concurrent first callers share one fetch.
  const [a, b] = await Promise.all([attestor.get(), attestor.get()]);
  assert.equal(fetches, 1);
  assert.equal(verifies, 1);
  assert.equal(a.hpkePublicKeyHex, b.hpkePublicKeyHex);
  assert.equal(attestor.state().verified, true);
  assert.equal(attestor.state().measurement, 'm');
  // Inside the TTL: cached.
  clock += 500;
  await attestor.get();
  assert.equal(fetches, 1);
  // Past the TTL: refetched.
  clock += 600;
  await attestor.get();
  assert.equal(fetches, 2);
  // A key rotation (422) invalidates regardless of TTL.
  attestor.invalidate();
  assert.equal(attestor.state().verified, false);
  const c = await attestor.get();
  assert.equal(fetches, 3);
  assert.equal(c.hpkePublicKeyHex.endsWith('3'), true);
});

test('an attestation failure surfaces to the caller and on state(), without the error text', async () => {
  const attestor = createTinfoilAttestor({
    enclaveHost: 'inference.tinfoil.sh',
    atcPort: 9455,
    fetchBundle: async () => {
      throw new Error('ECONNREFUSED atc details that must not leave');
    },
  });
  await assert.rejects(attestor.get(), /ECONNREFUSED/);
  const st = attestor.state();
  assert.equal(st.verified, false);
  assert.equal(st.last_error, 'failed');
  assert.equal(JSON.stringify(st).includes('ECONNREFUSED'), false);
  // Unconfigured (no ATC tunnel) is stated, not guessed.
  assert.equal(createTinfoilAttestor({ enclaveHost: 'x', atcPort: 0 }).state().configured, false);
});

// ─── live (opt-in) ──────────────────────────────────────────────────────────
// `TINFOIL_LIVE=1 node --test test/tinfoil.test.mjs` verifies a real bundle
// from ATC with the real verifier — the check the enclave performs at runtime,
// minus the tunnel. Needs network; never runs in CI.

test('live: a real ATC bundle for the pinned router verifies', { skip: process.env.TINFOIL_LIVE !== '1' }, async () => {
  const res = await fetch(`https://${TINFOIL_ATC_HOST}/attestation`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ enclaveUrl: 'https://inference.tinfoil.sh' }),
  });
  const bundle = await res.json();
  const v = await verifyTinfoilBundle(bundle, { enclaveHost: 'inference.tinfoil.sh' });
  assert.match(v.hpkePublicKeyHex, /^[0-9a-f]{64}$/);
  assert.match(v.measurement, /^[0-9a-f]{96}$/);
});

// ─── /private/attestation bundle cache ──────────────────────────────────────

test('createBundleCache: one ATC fetch per TTL, shared by concurrent misses, dropped by invalidate', async () => {
  let t = 0;
  let calls = 0;
  let release;
  const fetchBundle = () => {
    calls++;
    return new Promise((r) => (release = () => r({ n: calls })));
  };
  const cache = createBundleCache({ enclaveHost: 'h', atcPort: 1, fetchBundle, ttlMs: 1000, now: () => t });
  const burst = Promise.all(Array.from({ length: 50 }, () => cache.get()));
  release();
  const got = await burst;
  assert.equal(calls, 1);
  assert.ok(got.every((b) => b.n === 1));
  t = 999;
  assert.deepEqual(await cache.get(), { n: 1 });
  assert.equal(calls, 1);
  cache.invalidate();
  const next = cache.get();
  release();
  assert.deepEqual(await next, { n: 2 });
  t = 5000;
  const expired = cache.get();
  release();
  assert.deepEqual(await expired, { n: 3 });
});

test('createBundleCache: a failed fetch is not cached', async () => {
  let fail = true;
  const cache = createBundleCache({
    enclaveHost: 'h',
    atcPort: 1,
    fetchBundle: async () => {
      if (fail) throw new Error('atc down');
      return { ok: true };
    },
  });
  await assert.rejects(cache.get(), /atc down/);
  fail = false;
  assert.deepEqual(await cache.get(), { ok: true });
});
