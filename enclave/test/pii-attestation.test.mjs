// The PII detector is only ever reached through its verified attestation
// (pii/attestedDetector.mjs). These tests run the REAL attestor schedule
// (createTinfoilAttestor + verifyTinfoilBundle) with only the SEV-SNP/Sigstore
// verifier replaced, and a detector that is a real EHBP recipient, so "the
// detector received the text" means it could actually open it. Fixtures are
// fictional.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { EhbpRecipient } from '../src/ehbp-server.mjs';
import { createTinfoilAttestor, verifyTinfoilBundle, fetchTinfoilBundle, ATTESTATION_TTL_MS, ENCAP_KEY_HEADER } from '../src/tinfoil.mjs';
import { createAttestedDetector, DETECTOR_PLACEMENTS } from '../src/pii/attestedDetector.mjs';
import { piiFailureReason } from '../src/errorReport.mjs';

const HOST = 'detector.example.test';
const URL_ = `https://${HOST}/redact`;
const REPO = DETECTOR_PLACEMENTS['tinfoil-hosted'].configRepo;
const GOOD = 'a1'.repeat(48);
const BAD = 'b2'.repeat(48);
const TEXT = 'Hi, I am Jane Roe.';

/**
 * A stand-in for @tinfoilsh/verifier with the one rule these tests exercise:
 * the release's code measurement (here: the bundle digest, signed for REPO)
 * must equal the measurement in the enclave's report, else it throws — the
 * real verifier's compareMeasurements step.
 */
const fakeVerifier = ({ configRepo }) => ({
  async verifyBundle(b) {
    const report = JSON.parse(b.enclaveAttestationReport.body);
    if (report.repo !== configRepo) throw new Error('provenance is for another repo');
    if (report.measurement !== b.digest) throw new Error('measurement mismatch');
    return { hpkePublicKey: report.hpkePublicKey, measurement: { type: 'fake', registers: [report.measurement] } };
  },
});

function bundle({ domain = HOST, digest = GOOD, measurement = GOOD, repo = REPO, hpkePublicKey }) {
  return {
    domain,
    digest,
    vcek: 'VVVV',
    enclaveCert: 'CCCC',
    sigstoreBundle: {},
    enclaveAttestationReport: { format: 'fake', body: JSON.stringify({ repo, measurement, hpkePublicKey }) },
  };
}

/**
 * A fake hosted detector that is a real EHBP recipient. `fetch` is what the
 * adapter calls; `seen` records whether each request could be OPENED.
 */
async function sealedDetector() {
  const recipient = await EhbpRecipient.generate();
  const publicKeyHex = await recipient.publicKeyHex();
  const seen = [];
  const state = { mode: 'ok' };
  const fetch = async (url, init) => {
    const raw = Buffer.from(init.body);
    const encap = init.headers[ENCAP_KEY_HEADER];
    let opened = null;
    try {
      opened = encap ? await recipient.openRequest(encap, raw) : null;
    } catch {
      opened = null;
    }
    const text = opened ? JSON.parse(opened.plaintext.toString('utf8')).text : null;
    seen.push({ url, raw, auth: init.headers.authorization, opened: Boolean(opened), text });
    if (!opened) return { ok: false, status: 400 };
    if (state.mode === 'rotated') return { ok: false, status: 422 };
    const start = [...text].indexOf('J');
    const answer = JSON.stringify({ detected_spans: text.includes('Jane Roe') ? [{ label: 'private_person', start, end: start + 8 }] : [] });
    if (state.mode === 'plaintext') {
      return { ok: true, status: 200, headers: { get: () => null }, arrayBuffer: async () => Buffer.from(answer) };
    }
    const encryptor = await recipient.responseEncryptor(opened.exportedSecret, opened.requestEnc);
    const frame = await encryptor.encrypt(Buffer.from(answer));
    return {
      ok: true,
      status: 200,
      headers: { get: (n) => (n.toLowerCase() === 'ehbp-response-nonce' ? encryptor.responseNonceHex : null) },
      arrayBuffer: async () => frame,
    };
  };
  return { publicKeyHex, fetch, seen, state };
}

/** The production attestor, with only the network fetch and the SEV/Sigstore verifier faked. */
function attestorFor(atc, { now = Date.now } = {}) {
  return createTinfoilAttestor({
    enclaveHost: HOST,
    atcPort: 1,
    configRepo: REPO,
    now,
    fetchBundle: async (args) => {
      atc.calls.push(args);
      return atc.answer();
    },
    verify: (b, opts) => verifyTinfoilBundle(b, { ...opts, verifierImpl: fakeVerifier }),
  });
}

const make = (det, attestor, extra = {}) =>
  createAttestedDetector({ kind: 'tinfoil-hosted', url: URL_, apiKey: 'test-key', fetch: det.fetch, attestor, ...extra });

test('valid attestation: text is sealed to the attested key, the detector opens it, spans come back', async () => {
  const det = await sealedDetector();
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex }) };
  const d = make(det, attestorFor(atc));
  const { spans, calls } = await d.detect([TEXT, '']);
  assert.equal(calls, 1);
  assert.deepEqual(spans, [[{ start: 9, end: 17, cls: 'PERSON' }], []]);
  assert.equal(det.seen.length, 1);
  assert.equal(det.seen[0].opened, true);
  assert.equal(det.seen[0].text, TEXT);
  assert.equal(det.seen[0].auth, 'Bearer test-key');
  assert.equal(det.seen[0].raw.includes(Buffer.from('Jane Roe')), false, 'the wire body is ciphertext');
  // ATC was asked for THIS host's bundle under THIS placement's config repo.
  assert.deepEqual(atc.calls, [{ atcPort: 1, enclaveHost: HOST, configRepo: REPO }]);
});

for (const [name, answer] of [
  ['wrong measurement', (k) => bundle({ hpkePublicKey: k, measurement: BAD })],
  ['provenance for another repo', (k) => bundle({ hpkePublicKey: k, repo: 'someone/else' })],
  ['bundle for another host', (k) => bundle({ hpkePublicKey: k, domain: 'other.example.test' })],
  ['attestation fetch fails', () => { throw new Error('ATC: HTTP 503'); }],
  ['verified attestation carries no key', () => bundle({ hpkePublicKey: '' })],
]) {
  test(`fail closed — ${name}: rejects "attestation" and the detector is never called`, async () => {
    const det = await sealedDetector();
    const atc = { calls: [], answer: () => answer(det.publicKeyHex) };
    const d = make(det, attestorFor(atc));
    await assert.rejects(d.detect([TEXT]), (e) => e.code === 'pii_detector_failed' && e.reason === 'attestation');
    assert.equal(det.seen.length, 0, 'no bytes reached the detector');
    assert.equal(piiFailureReason({ reason: 'attestation' }), 'ATTESTATION');
  });
}

test('a failed attestation is not cached: the next request re-verifies', async () => {
  const det = await sealedDetector();
  let measurement = BAD;
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex, measurement }) };
  const d = make(det, attestorFor(atc));
  await assert.rejects(d.detect([TEXT]), { reason: 'attestation' });
  measurement = GOOD;
  assert.equal((await d.detect([TEXT])).calls, 1);
  assert.equal(atc.calls.length, 2);
});

test('the cache cannot mask a changed measurement beyond its TTL', async () => {
  const det = await sealedDetector();
  let t = 1_000_000;
  let measurement = GOOD;
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex, measurement }) };
  const d = make(det, attestorFor(atc, { now: () => t }));
  assert.equal((await d.detect([TEXT])).calls, 1);
  // The detector is redeployed with code whose measurement no longer matches.
  measurement = BAD;
  t += ATTESTATION_TTL_MS - 1;
  assert.equal((await d.detect([TEXT])).calls, 1, 'inside the TTL the verified key is reused');
  assert.equal(atc.calls.length, 1);
  t += 1;
  const before = det.seen.length;
  await assert.rejects(d.detect([TEXT]), { reason: 'attestation' });
  assert.equal(atc.calls.length, 2, 'the TTL forced a re-verification');
  assert.equal(det.seen.length, before, 'nothing was sent after the re-verification failed');
});

test('a 422 (detector rotated its key) fails the request and forces re-attestation', async () => {
  const det = await sealedDetector();
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex }) };
  const d = make(det, attestorFor(atc));
  await d.detect([TEXT]);
  det.state.mode = 'rotated';
  await assert.rejects(d.detect([TEXT]), { reason: 'http_status', status: 422 });
  det.state.mode = 'ok';
  await d.detect([TEXT]);
  assert.equal(atc.calls.length, 2);
});

test('an endpoint that is not the attested enclave cannot read the text', async () => {
  // Attestation is valid, but it vouches for a DIFFERENT key than the one the
  // endpoint on the other end of the tunnel holds (a substituted detector).
  const det = await sealedDetector();
  const attested = await EhbpRecipient.generate();
  const atc = { calls: [], answer: async () => bundle({ hpkePublicKey: await attested.publicKeyHex() }) };
  const d = make(det, attestorFor(atc));
  await assert.rejects(d.detect([TEXT]), { reason: 'http_status' });
  assert.equal(det.seen.length, 1);
  assert.equal(det.seen[0].opened, false, 'the substitute could not open the body');
  assert.equal(det.seen[0].raw.includes(Buffer.from('Jane Roe')), false);
});

test('a reply that is not sealed to this request is refused as bad_response', async () => {
  const det = await sealedDetector();
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex }) };
  const d = make(det, attestorFor(atc));
  det.state.mode = 'plaintext';
  await assert.rejects(d.detect([TEXT]), { reason: 'bad_response' });
});

test('no attestor is a configuration error, not an unattested detector', async () => {
  const det = await sealedDetector();
  assert.throws(() => make(det, undefined), { reason: 'bad_config' });
  assert.throws(() => make(det, { get: async () => ({}) }), { reason: 'bad_config' });
});

test('all-empty input neither attests nor sends', async () => {
  const det = await sealedDetector();
  const atc = { calls: [], answer: () => bundle({ hpkePublicKey: det.publicKeyHex }) };
  const d = make(det, attestorFor(atc));
  assert.deepEqual(await d.detect(['', '  ']), { spans: [[], []], calls: 0, inputTokens: 0, inputTokensEstimated: false });
  assert.equal(atc.calls.length, 0);
  assert.equal(det.seen.length, 0);
});

test('a caller abort while attestation is pending rejects "aborted" and sends nothing', async () => {
  const det = await sealedDetector();
  let release;
  const atc = { calls: [], answer: () => new Promise((r) => { release = () => r(bundle({ hpkePublicKey: det.publicKeyHex })); }) };
  const d = make(det, attestorFor(atc));
  const ctrl = new AbortController();
  const p = d.detect([TEXT], { signal: ctrl.signal });
  await new Promise((r) => setImmediate(r));
  ctrl.abort();
  await assert.rejects(p, { reason: 'aborted' });
  release();
  assert.equal(det.seen.length, 0);
});

test('fetchTinfoilBundle names the config repo for a non-router enclave, as the Tinfoil SDK does', async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    await fetchTinfoilBundle({ atcPort: server.address().port, enclaveHost: HOST, configRepo: REPO, requestImpl: http.request });
    assert.deepEqual(seen[0], { enclaveUrl: `https://${HOST}`, repo: REPO });
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});
