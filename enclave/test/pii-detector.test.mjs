import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createDetector, DetectorError, DEFAULT_TIMEOUT_MS, HOSTED_LABELS } from '../src/pii/detector.mjs';
import { pseudonymize } from '../src/pii/core.mjs';

const URL_ = 'https://detector.example.test/redact';

// Python-style code-point offsets of `sub` in `text` (what both placements return).
const cp = (text, sub, from = 0) => {
  const u = text.indexOf(sub, from);
  const start = [...text.slice(0, u)].length;
  return { start, end: start + [...sub].length };
};

function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    const r = await handler(JSON.parse(init.body), init);
    if (r instanceof Error) throw r;
    const { status = 200, json } = r;
    return { ok: status >= 200 && status < 300, status, json: async () => (typeof json === 'function' ? json() : json) };
  };
  fn.calls = calls;
  return fn;
}

// A fake hosted filter: finds fixed fictional surfaces in the joined text.
const SURFACES = { 'Jane Roe': 'private_person', 'jane.roe@example.com': 'private_email', '2001-02-03': 'private_date' };
const hostedHandler = ({ text }) => {
  const detected_spans = [];
  for (const [s, label] of Object.entries(SURFACES)) {
    for (let i = text.indexOf(s); i >= 0; i = text.indexOf(s, i + 1)) detected_spans.push({ label, ...cp(text, s, i), text: s, placeholder: 'x' });
  }
  return { json: { detected_spans, redacted_text: 'ignored' } };
};
const hosted = (fetch, extra) => createDetector({ kind: 'tinfoil-hosted', url: URL_, apiKey: 'test-key', fetch, ...extra });
const surfaces = (texts, spans) => spans.map((ss, i) => [...ss].sort((a, b) => a.start - b.start).map((s) => texts[i].slice(s.start, s.end)));

test('PII-03: hosted — texts joined in ONE call, offsets mapped back per text', async () => {
  const f = fakeFetch(hostedHandler);
  const texts = ['Hi Jane Roe', '', 'mail jane.roe@example.com or Jane Roe', '   '];
  const { spans, calls } = await hosted(f).detect(texts);
  assert.equal(calls, 1);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].body.text, 'Hi Jane Roe\n\nmail jane.roe@example.com or Jane Roe', 'empty texts are not sent');
  assert.equal(f.calls[0].init.headers.authorization, 'Bearer test-key');
  assert.deepEqual(surfaces(texts, spans), [['Jane Roe'], [], ['jane.roe@example.com', 'Jane Roe'], []]);
  assert.deepEqual(spans[0], [{ start: 3, end: 11, cls: 'PERSON' }]);
  assert.deepEqual(spans[2].map((x) => x.cls).sort(), ['EMAIL', 'PERSON']);
});

test('PII-18: code-point offsets are converted to UTF-16 (astral chars before the span)', async () => {
  const f = fakeFetch(hostedHandler);
  const texts = ['😀😀 hi', '𝒳 I am Jane Roe 😀, jane.roe@example.com'];
  const { spans } = await hosted(f).detect(texts);
  assert.deepEqual(surfaces(texts, spans), [[], ['Jane Roe', 'jane.roe@example.com']]);
  // …and the result feeds pseudonymize() without an invalid-span error.
  assert.equal(pseudonymize(texts, spans).texts[1], '𝒳 I am [PERSON_1] 😀, [EMAIL_1]');
});

test('self-hosted: {texts} batch, code-point offsets converted, empty texts skipped', async () => {
  const texts = ['😀 Jane Roe', '', 'Acme Corp'];
  const f = fakeFetch(({ texts: sent }) => ({ json: { windows: 2, spans: [
    [{ ...cp(sent[0], 'Jane Roe'), cls: 'PERSON', score: 0.9 }],
    [{ start: 0, end: 9, cls: 'ORG', score: 0.8 }],
  ] } }));
  const d = createDetector({ kind: 'tinfoil-self', url: URL_, fetch: f });
  const { spans, calls } = await d.detect(texts);
  assert.equal(calls, 1);
  assert.deepEqual(f.calls[0].body, { texts: ['😀 Jane Roe', 'Acme Corp'] });
  assert.equal(f.calls[0].init.headers.authorization, undefined, 'no key ⇒ no Authorization header');
  assert.deepEqual(surfaces(texts, spans), [['Jane Roe'], [], ['Acme Corp']]);
});

test('all-empty input makes no request', async () => {
  const f = fakeFetch(hostedHandler);
  assert.deepEqual(await hosted(f).detect(['', ' \n']), { spans: [[], []], calls: 0 });
  assert.deepEqual(await hosted(f).detect([]), { spans: [], calls: 0 });
  assert.equal(f.calls.length, 0);
});

test('label map: every hosted label maps to a v1 class or is dropped; private_date is dropped', async () => {
  for (const cls of Object.values(HOSTED_LABELS)) assert.ok(cls === null || ['PERSON', 'EMAIL', 'PHONE', 'ADDRESS', 'ID', 'IP'].includes(cls));
  const { spans } = await hosted(fakeFetch(hostedHandler)).detect(['born 2001-02-03, Jane Roe']);
  assert.deepEqual(spans[0].map((s) => s.cls), ['PERSON']);
});

test('span edges: surrounding punctuation/space trimmed; spans crossing the separator are clipped', async () => {
  const texts = ['name: (Jane Roe).', 'Roe x'];
  const f = fakeFetch(({ text }) => ({ json: { detected_spans: [
    { label: 'private_person', start: 6, end: 17 }, // " (Jane Roe)."  -> trimmed
    { label: 'private_person', start: 12, end: 22 }, // "Roe).\n\nRoe"   -> crosses the separator
  ] } }));
  const { spans } = await hosted(f).detect(texts);
  assert.deepEqual(surfaces(texts, spans), [['Jane Roe', 'Roe'], ['Roe']]);
});

async function rejectsWith(p, reason) {
  await assert.rejects(p, (e) => {
    assert.ok(e instanceof DetectorError);
    assert.equal(e.reason, reason);
    assert.equal(e.code, 'pii_detector_failed');
    assert.ok(!e.message.includes('Jane'), 'error message never carries text');
    return true;
  });
}

test('PII-07: fail closed — http status, network, malformed body, unknown label', async () => {
  const t = ['Jane Roe'];
  await rejectsWith(hosted(fakeFetch(() => ({ status: 500, json: { error: 'Jane Roe' } }))).detect(t), 'http_status');
  await rejectsWith(hosted(fakeFetch(() => new TypeError('fetch failed'))).detect(t), 'network');
  await rejectsWith(hosted(fakeFetch(() => ({ json: { nope: 1 } }))).detect(t), 'bad_response');
  await rejectsWith(hosted(fakeFetch(() => ({ json: () => { throw new SyntaxError('x'); } }))).detect(t), 'bad_response');
  await rejectsWith(hosted(fakeFetch(() => ({ json: { detected_spans: [{ label: 'private_person', start: 0, end: 99 }] } }))).detect(t), 'bad_response');
  await rejectsWith(hosted(fakeFetch(() => ({ json: { detected_spans: [{ label: 'private_person', start: 3, end: 1 }] } }))).detect(t), 'bad_response');
  await rejectsWith(hosted(fakeFetch(() => ({ json: { detected_spans: [{ label: 'private_zodiac', start: 0, end: 4 }] } }))).detect(t), 'unknown_label');
  const self = (json) => createDetector({ kind: 'tinfoil-self', url: URL_, fetch: fakeFetch(() => ({ json })) }).detect(t);
  await rejectsWith(self({ spans: [] }), 'bad_response');
  await rejectsWith(self({ spans: [[{ start: 0, end: 4, cls: 'DOB' }]] }), 'unknown_label');
  await rejectsWith(self({ spans: [[{ start: 0, end: 1.5, cls: 'PERSON' }]] }), 'bad_response');
});

// fetch that only settles when aborted.
const hangingFetch = () => fakeFetch((_b, init) => new Promise((_, reject) => {
  init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
}));

test('PII-07: default timeout is 60 s — 59,999 ms still pending, 60,000 ms rejects "timeout"', async (t) => {
  assert.equal(DEFAULT_TIMEOUT_MS, 60_000);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let settled = false;
  const p = hosted(hangingFetch()).detect(['Jane Roe']);
  p.catch(() => {}).finally(() => { settled = true; });
  await new Promise((r) => queueMicrotask(r));
  t.mock.timers.tick(59_999);
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.equal(settled, false);
  t.mock.timers.tick(1);
  await rejectsWith(p, 'timeout');
});

test('PII-07: timeout is configurable', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const p = hosted(hangingFetch(), { timeoutMs: 5_000 }).detect(['Jane Roe']);
  await new Promise((r) => queueMicrotask(r));
  t.mock.timers.tick(5_000);
  await rejectsWith(p, 'timeout');
});

test('timeout also covers a slow response body', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = async (_u, init) => ({ ok: true, status: 200, json: () => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted')))) });
  const p = hosted(f).detect(['Jane Roe']);
  for (let i = 0; i < 5; i++) await Promise.resolve();
  t.mock.timers.tick(DEFAULT_TIMEOUT_MS);
  await rejectsWith(p, 'timeout');
});

test('caller abort signal rejects with "aborted" (already-aborted and mid-flight)', async () => {
  const pre = new AbortController();
  pre.abort();
  const f = hangingFetch();
  await rejectsWith(hosted(f).detect(['Jane Roe'], { signal: pre.signal }), 'aborted');
  assert.equal(f.calls.length, 0, 'no request once already aborted');
  const mid = new AbortController();
  const p = hosted(hangingFetch()).detect(['Jane Roe'], { signal: mid.signal });
  mid.abort();
  await rejectsWith(p, 'aborted');
});

test('bad config is rejected up front', () => {
  for (const cfg of [{ kind: 'nope', url: URL_ }, { kind: 'tinfoil-hosted' }, { kind: 'tinfoil-hosted', url: 'ftp://x' }, { kind: 'tinfoil-hosted', url: URL_, timeoutMs: 0 }]) {
    assert.throws(() => createDetector({ fetch: () => {}, ...cfg }), (e) => e.reason === 'bad_config');
  }
});
