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
    for (const a of s.hp.authorizes) assert.ok(!Object.hasOwn(a.body, 'pii_redaction'), 'the field never reaches hp');
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

  // The early guard only sees the model the caller sent. horse-power may
  // resolve a public alias onto a private/* model, or answer with a Tinfoil
  // candidate; either body would be sealed to Tinfoil and cannot be redacted,
  // so the post-authorize guard must refuse it before any spend.
  for (const [label, extra] of [
    ['hp resolves the alias to a private/* model', () => ({ resolved_model: 'private/some-model' })],
    ['hp answers with a Tinfoil upstream for a public model', (body) => ({
      resolved_model: body.model, upstreams: [{ provider: 'tinfoil', model: 'some-model' }],
    })],
  ]) {
    await t.test(`true and ${label}: 400 pii_redaction_unsupported_model, no upstream, no settle`, async () => {
      const auths = s.hp.authorizes.length;
      const ors = s.or.requests.length;
      const settles = s.hp.settles.length;
      const dets = s.detector.requests.length;
      s.hp.authorizeExtra = extra;
      try {
        const r = await s.chat(req({ pii_redaction: true, messages: [{ role: 'user', content: 'mail Jane Roe at jane.roe@example.com' }] }));
        assert.equal(r.status, 400, r.text);
        assert.equal(JSON.parse(r.text).error.code, 'pii_redaction_unsupported_model');
        assert.equal(s.hp.authorizes.length, auths + 1, 'refused after authorize, on hp\'s resolution');
        // Give any stray settle or upstream call time to land before counting.
        await new Promise((ok) => setTimeout(ok, 300));
        assert.equal(s.or.requests.length, ors, 'no upstream call');
        assert.equal(s.hp.settles.length, settles, 'no settle');
        assert.equal(s.detector.requests.length, dets, 'the detector is not asked');
      } finally {
        s.hp.authorizeExtra = null;
      }
    });
  }

  await t.test('true: the field never reaches the model upstream', async () => {
    await s.chat(req({ pii_redaction: true }));
    neverForwarded();
  });
});
