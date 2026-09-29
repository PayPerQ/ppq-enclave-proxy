// The detector's attestation gates redaction end to end, through the real
// server: a wrong measurement or an unreachable ATC means the text never
// leaves (the detector sees nothing), the client gets 503
// pii_redaction_unavailable, nothing goes upstream, nothing is settled, and the
// error report says ATTESTATION. A valid attestation lets the same request
// through with the text sealed on the wire. Fixtures are fictional.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { startPiiStack, haveOpenssl, DETECTOR_REPO, GOOD_MEASUREMENT } from './piiServerHarness.mjs';

const MODEL = 'openai/gpt-4.1-mini';
const PROMPT = 'Hi, I am Jane Roe, write to jane.roe@example.com';
const SURFACE = Buffer.from('Jane Roe');

const echoJson = (body) => ({
  status: 200, contentType: 'application/json',
  body: JSON.stringify({ id: 'gen-1', object: 'chat.completion', model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: `You said: ${body.messages.at(-1).content}` }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 } }),
});

const health = (port) => new Promise((resolve, reject) => {
  https.get({ host: '127.0.0.1', port, path: '/health', rejectUnauthorized: false, agent: false }, (res) => {
    let t = '';
    res.on('data', (d) => { t += d; });
    res.on('end', () => resolve(JSON.parse(t)));
  }).on('error', reject);
});

test('detector attestation gates pii_redaction end to end', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const s = await startPiiStack({ extraEnv: { PII_DETECTOR_TIMEOUT_MS: '2000' } });
  t.after(() => s.stop());
  s.or.respond = echoJson;
  // Error reports need an enclave-shaped id: enc-<ms>-<[a-z0-9]{1,12}>.
  const chat = (tag) => s.chat({ model: MODEL, pii_redaction: true, messages: [{ role: 'user', content: PROMPT }] },
    { requestId: `enc-${Date.now()}-${tag}` });

  // Failures first: a failed attestation is never cached, a good one is (TTL).
  for (const [name, setup] of [
    ['wrong measurement', () => { s.atc.measurement = 'b2'.repeat(48); }],
    ['provenance for another repo', () => { s.atc.repo = 'someone/else'; }],
    ['ATC unreachable', () => { s.atc.mode = 'error'; }],
  ]) {
    await t.test(`${name}: 503, the detector never receives the text, zero upstream, zero settles, reason ATTESTATION`, async () => {
      Object.assign(s.atc, { mode: 'ok', measurement: GOOD_MEASUREMENT, repo: DETECTOR_REPO });
      setup();
      const atcCalls = s.atc.requests.length;
      const detects = s.detector.requests.length;
      const ors = s.or.requests.length;
      const settles = s.hp.settles.length;
      const r = await chat(`att${s.atc.requests.length}`);
      assert.equal(r.status, 503, r.text);
      assert.equal(JSON.parse(r.text).error.code, 'pii_redaction_unavailable');
      assert.ok(s.atc.requests.length > atcCalls, 'the attestation was asked for');
      const report = await s.waitFor(() => s.hp.errors.find((e) => e.request_id === r.requestId), 'the error report');
      assert.equal(report.code, 'pii_detector_failed');
      assert.equal(report.reason, 'ATTESTATION');
      await new Promise((ok) => setTimeout(ok, 200));
      assert.equal(s.detector.requests.length, detects, 'no bytes reached the detector');
      assert.equal(s.or.requests.length, ors, 'nothing sent upstream');
      assert.equal(s.hp.settles.length, settles, 'nothing settled');
    });
  }

  await t.test('valid attestation: redacted, the detector opened a sealed body, ATC asked for the placement repo', async () => {
    Object.assign(s.atc, { mode: 'ok', measurement: GOOD_MEASUREMENT, repo: DETECTOR_REPO });
    const r = await chat('ok');
    assert.equal(r.status, 200, r.text);
    assert.equal(JSON.parse(r.text).choices[0].message.content, `You said: ${PROMPT}`);
    const d = s.detector.requests.at(-1);
    assert.equal(d.sealed, true);
    assert.equal(d.body.text, PROMPT);
    assert.equal(d.raw.includes(SURFACE), false, 'ciphertext on the wire');
    assert.equal(s.or.requests.at(-1).raw.includes(SURFACE), false);
    const asked = s.atc.requests.at(-1);
    assert.equal(asked.url, '/attestation');
    assert.equal(asked.host, 'atc.tinfoil.sh');
    assert.deepEqual(asked.body, { enclaveUrl: 'https://localhost', repo: DETECTOR_REPO });
    const h = await health(s.inboundPort);
    assert.equal(h.pii_detector_attestation.verified, true);
    assert.equal(h.pii_detector_attestation.measurement, GOOD_MEASUREMENT);
    assert.equal(h.pii_redaction.failures.attestation, 3);
  });
});
