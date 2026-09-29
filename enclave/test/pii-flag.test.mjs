// `pii_redaction` on /v1/chat/completions is judged by value, and the field
// itself is never forwarded: not to horse-power, not to the model upstream.
// Asserted at the fakes (what they received) and at the client (status/code).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startPiiStack, haveOpenssl } from './piiServerHarness.mjs';

const MODEL = 'openai/gpt-4.1-mini';
const okJson = () => ({
  status: 200, contentType: 'application/json',
  body: JSON.stringify({ id: 'gen-1', object: 'chat.completion', model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: 'hello' }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 } }),
});
const req = (extra) => ({ model: MODEL, stream: false, messages: [{ role: 'user', content: 'hi' }], ...extra });

test('pii_redaction is judged by value and never forwarded', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const s = await startPiiStack();
  s.or.respond = okJson;
  t.after(() => s.stop());

  const neverForwarded = () => {
    for (const a of s.hp.authorizes) assert.equal(Object.hasOwn(a.body, 'pii_redaction') && a.body.pii_redaction !== true, false, 'authorize only ever carries the reservation marker');
    for (const r of s.or.requests) assert.ok(!r.raw.includes('pii_redaction'), 'the field never reaches the model upstream');
  };

  await t.test('absent: served, nothing added', async () => {
    const r = await s.chat(req({}));
    assert.equal(r.status, 200);
    assert.equal(s.or.requests.length, 1);
    neverForwarded();
  });

  await t.test('false: served with the field stripped', async () => {
    const before = s.or.requests.length;
    const r = await s.chat(req({ pii_redaction: false }));
    assert.equal(r.status, 200);
    assert.equal(s.or.requests.length, before + 1);
    neverForwarded();
  });

  for (const [label, value] of [['a string', 'yes'], ['null', null], ['a number', 1], ['an object', {}]]) {
    await t.test(`${label}: 400 pii_redaction_invalid, nothing sent anywhere`, async () => {
      const auths = s.hp.authorizes.length;
      const ors = s.or.requests.length;
      const r = await s.chat(req({ pii_redaction: value }));
      assert.equal(r.status, 400);
      assert.equal(JSON.parse(r.text).error.code, 'pii_redaction_invalid');
      assert.equal(s.hp.authorizes.length, auths, 'no authorize');
      assert.equal(s.or.requests.length, ors, 'no upstream call');
    });
  }

  await t.test('true with a private/* model: 400 pii_redaction_unsupported_model before authorize', async () => {
    const auths = s.hp.authorizes.length;
    const ors = s.or.requests.length;
    const r = await s.chat({ ...req({ pii_redaction: true }), model: 'private/some-model' });
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.text).error.code, 'pii_redaction_unsupported_model');
    assert.equal(s.hp.authorizes.length, auths);
    assert.equal(s.or.requests.length, ors);
    assert.equal(s.detector.requests.length, 0, 'the detector is not asked');
  });

  await t.test('true: the field never reaches the model upstream', async () => {
    await s.chat(req({ pii_redaction: true }));
    neverForwarded();
  });
});
