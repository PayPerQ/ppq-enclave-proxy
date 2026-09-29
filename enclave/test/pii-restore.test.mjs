import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pseudonymize, GRAMMARS } from '../src/pii/core.mjs';
import { createRestorer, restoreText } from '../src/pii/restore.mjs';

// Fictional PII only.
function mappingOf(entries, grammar = 'square') {
  return { byPlaceholder: new Map(entries), grammar: GRAMMARS[grammar] };
}
const M = mappingOf([
  ['[PERSON_1]', 'Jane Roe'],
  ['[PERSON_12]', 'John Doe'],
  ['[EMAIL_1]', 'jane.roe@example.com'],
]);

const stream = (r, chunks) => chunks.map((c) => r.push(c)).join('') + r.flush();

test('restoreText replaces every issued placeholder', () => {
  assert.equal(
    restoreText('Dear [PERSON_1], we wrote to [EMAIL_1]. Cc [PERSON_12].', M),
    'Dear Jane Roe, we wrote to jane.roe@example.com. Cc John Doe.',
  );
});

test('round trip through pseudonymize restores the original surfaces', () => {
  const t = 'I am Jane Roe (jane.roe@example.com).';
  const { texts, mapping } = pseudonymize([t], [[{ start: 5, end: 13, cls: 'PERSON' }, { start: 15, end: 35, cls: 'EMAIL' }]]);
  assert.equal(restoreText(texts[0], mapping), t);
});

test('unknown placeholder is delivered verbatim (never mapped to other data)', () => {
  assert.equal(restoreText('[PERSON_2] and [PHONE_1] and [PERSON_1]', M), '[PERSON_2] and [PHONE_1] and Jane Roe');
});

test('restoration is single-pass: a surface that looks like a placeholder is not re-restored', () => {
  const m = mappingOf([['[PERSON_1]', 'literally [PERSON_2]'], ['[PERSON_2]', 'Jane Roe']]);
  assert.equal(restoreText('[PERSON_1]', m), 'literally [PERSON_2]');
});

test('PII-19: a placeholder split across 2 chunks is restored, never emitted partially', () => {
  const r = createRestorer(M);
  const a = r.push('Hello [PERS');
  assert.equal(a, 'Hello ');
  const b = r.push('ON_1], bye');
  assert.equal(b, 'Jane Roe, bye');
  assert.equal(r.flush(), '');
});

test('PII-19: a placeholder split across N single-character chunks is restored', () => {
  const r = createRestorer(M);
  const text = 'x [EMAIL_1] y [PERSON_12] z';
  const outs = [...text].map((c) => r.push(c));
  for (const o of outs) assert.ok(!/\[[A-Z]/.test(o) || o === '', `partial placeholder leaked: ${o}`);
  assert.equal(outs.join('') + r.flush(), 'x jane.roe@example.com y John Doe z');
});

test('PII-19: a prefix of a longer placeholder is held until it resolves', () => {
  const r = createRestorer(M);
  assert.equal(r.push('[PERSON_1'), '');
  assert.equal(r.push('2]'), 'John Doe');
  const r2 = createRestorer(M);
  assert.equal(r2.push('[PERSON_1'), '');
  assert.equal(r2.push('] ok'), 'Jane Roe ok');
});

test('PII-22: stream ending mid-prefix flushes the buffered text as-is', () => {
  const r = createRestorer(M);
  assert.equal(r.push('see [PERSO'), 'see ');
  assert.equal(r.flush(), '[PERSO');
  assert.equal(r.flush(), '', 'flush is idempotent');
});

test('PII-22: nothing is dropped when a held prefix turns out not to be a placeholder', () => {
  const r = createRestorer(M);
  assert.equal(stream(r, ['array[PE', 'NDING] x']), 'array[PENDING] x');
});

test('the buffer is bounded by the longest issued placeholder', () => {
  const r = createRestorer(M);
  const out = r.push('[PERSON_1' + 'x'.repeat(10_000));
  assert.equal(out.length, 10_009);
  // text that can never become a placeholder is released immediately
  assert.equal(createRestorer(M).push('[not a placeholder at all'), '[not a placeholder at all');
});

test('empty mapping: restorer is a pass-through with no buffering', () => {
  const r = createRestorer(mappingOf([]));
  assert.equal(r.push('[PERS'), '[PERS');
  assert.equal(r.flush(), '');
});

test('stats count restored and unknown placeholders', () => {
  const r = createRestorer(M);
  stream(r, ['[PERSON_1] [PERSON_3] [EM', 'AIL_1]']);
  assert.deepEqual(r.stats, { restored: 2, unknown: 1 });
});

test('json mode escapes the surface for a JSON string context (tool-call arguments)', () => {
  const m = mappingOf([['[PERSON_1]', 'Jane "JR" Roe\\n']]);
  const r = createRestorer(m, { json: true });
  const args = stream(r, ['{"name":"[PER', 'SON_1]"}']);
  assert.deepEqual(JSON.parse(args), { name: 'Jane "JR" Roe\\n' });
  assert.equal(JSON.parse(restoreText('{"n":"[PERSON_1]"}', m, { json: true })).n, 'Jane "JR" Roe\\n');
});

test('other grammars restore and buffer with their own delimiters', () => {
  for (const g of ['whiteSquare', 'angle']) {
    const { open, close } = GRAMMARS[g];
    const ph = `${open}PERSON_1${close}`;
    const m = mappingOf([[ph, 'Jane Roe']], g);
    const r = createRestorer(m);
    assert.equal(stream(r, [`hi ${ph.slice(0, 3)}`, `${ph.slice(3)}!`]), 'hi Jane Roe!');
    // the square grammar is NOT a placeholder under another grammar
    assert.equal(restoreText('[PERSON_1]', m), '[PERSON_1]');
  }
});

// Property: for any chunking, streaming restore == whole-string restore.
function prng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

test('property: any chunking of a string restores identically to restoreText', () => {
  const rand = prng(0xc0ffee);
  const atoms = ['[PERSON_1]', '[PERSON_12]', '[EMAIL_1]', '[PERSON_2]', '[PERS', 'ON_1]', '[', ']', 'É', '😀', ' ', 'a', '[PERSON_', '_1]', '\n'];
  for (let iter = 0; iter < 2000; iter++) {
    let s = '';
    const n = 1 + Math.floor(rand() * 12);
    for (let i = 0; i < n; i++) s += atoms[Math.floor(rand() * atoms.length)];
    const expected = restoreText(s, M);
    const chunks = [];
    let i = 0;
    while (i < s.length) {
      const k = 1 + Math.floor(rand() * 5);
      chunks.push(s.slice(i, i + k));
      i += k;
    }
    const r = createRestorer(M);
    assert.equal(stream(r, chunks), expected, `chunks=${JSON.stringify(chunks)}`);
  }
});
