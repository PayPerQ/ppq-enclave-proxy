// Redaction telemetry is counts, timings and reason tokens: whatever the
// server logs, reports to horse-power or shows on /health, no surface, no
// placeholder and no piece of the mapping is ever in it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { startPiiStack, haveOpenssl, SURFACES } from './piiServerHarness.mjs';

const MODEL = 'openai/gpt-4.1-mini';
const PROMPT = 'Hi, I am Jane Roe, write to jane.roe@example.com';
const PLACEHOLDER = /⟦[A-Z]+_[0-9]+⟧/;

function echoSse(body) {
  const text = `You said: ${body.messages.at(-1).content}`;
  const ev = (o) => `data: ${JSON.stringify({ id: 'gen-t', object: 'chat.completion.chunk', model: MODEL, ...o })}\n\n`;
  const sse = ev({ choices: [{ index: 0, delta: { role: 'assistant', content: text }, finish_reason: null }] })
    + ev({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })
    + ev({ choices: [], usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 } })
    + 'data: [DONE]\n\n';
  return { status: 200, contentType: 'text/event-stream', body: sse, chunkBytes: 7 };
}

const health = (port) => new Promise((resolve, reject) => {
  https.get({ host: '127.0.0.1', port, path: '/health', rejectUnauthorized: false, agent: false }, (res) => {
    let t = '';
    res.on('data', (d) => { t += d; });
    res.on('end', () => resolve(t));
  }).on('error', reject);
});

test('pii telemetry carries no content', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const s = await startPiiStack({ extraEnv: { PII_DETECTOR_TIMEOUT_MS: '300' } });
  t.after(() => s.stop());
  s.or.respond = echoSse;

  const ok = await s.chat({ model: MODEL, stream: true, pii_redaction: true, messages: [{ role: 'user', content: PROMPT }] });
  assert.equal(ok.status, 200, ok.text);
  assert.ok(ok.text.includes('Jane Roe'), 'the client still gets its words back');
  await s.waitFor(() => s.hp.settles.find((x) => x.request_id === ok.requestId), 'the settle');

  s.detector.mode = 'error';
  // An enclave-shaped id: the only kind an error report carries (errorReport.mjs).
  const failed = await s.chat({ model: MODEL, pii_redaction: true, messages: [{ role: 'user', content: PROMPT }] },
    { requestId: `enc-${Date.now()}-pii1` });
  s.detector.mode = 'ok';
  assert.equal(failed.status, 503);
  const report = await s.waitFor(() => s.hp.errors.find((e) => e.code === 'pii_detector_failed'), 'the error report');
  assert.equal(report.request_id, failed.requestId);
  assert.match(report.reason, /^[A-Z][A-Z0-9_]{1,40}$/);
  assert.equal(report.reason, 'HTTP_STATUS');

  const healthText = await health(s.inboundPort);
  const pii = JSON.parse(healthText).pii_redaction;
  assert.equal(pii.redacted, 1);
  assert.equal(pii.detector_calls, 1);
  assert.equal(pii.input_tokens, s.detector.inputTokens);
  assert.equal(pii.input_tokens_estimated_calls, 0);
  assert.equal(pii.entities, 2);
  assert.equal(pii.restorations, 1);
  assert.equal(pii.restoration_misses, 0);
  assert.deepEqual(pii.failures, { http_status: 1 });
  assert.equal(Object.values(pii.latency_ms).reduce((a, b) => a + b, 0), 1);

  // Everything the enclave said about these requests, anywhere but the client.
  const said = [s.logs, JSON.stringify(s.hp.errors), JSON.stringify(s.hp.settles), JSON.stringify(s.hp.authorizes), healthText].join('\n');
  for (const [surface] of SURFACES) assert.ok(!said.includes(surface), `"${surface}" leaked into telemetry`);
  assert.doesNotMatch(said, PLACEHOLDER, 'no placeholder in telemetry');
  assert.doesNotMatch(said, /Jane|Roe|example\.com/, 'no piece of a surface either');
});
