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
    // square brackets are NOT this grammar's delimiters: an unissued token
    // stays verbatim, an issued one is restored as a bare token (lenient)
    assert.equal(restoreText('[PERSON_2]', m), '[PERSON_2]');
    assert.equal(restoreText('[PERSON_1]', m), '[Jane Roe]');
  }
});

// Lenient restore: models sometimes drop the brackets ("PERSON_1") or, inside
// JSON, write them as \uXXXX escapes. Only issued placeholders are affected.
const W = mappingOf([
  ['⟦PERSON_1⟧', 'Jane Roe'],
  ['⟦PERSON_12⟧', 'John Doe'],
  ['⟦EMAIL_1⟧', 'jane.roe@example.com'],
], 'whiteSquare');

test('lenient: a bare CLASS_n of an issued placeholder is restored', () => {
  assert.equal(restoreText('Dear PERSON_1, mail EMAIL_1. Cc PERSON_12.', W), 'Dear Jane Roe, mail jane.roe@example.com. Cc John Doe.');
  assert.equal(restoreText('PERSON_1', W), 'Jane Roe', 'start and end of string are boundaries');
  assert.equal(restoreText('(PERSON_1)', W), '(Jane Roe)');
});

test('lenient: bare restore is word-boundary safe', () => {
  // a longer index is its own token, never a prefix match of a shorter one
  assert.equal(restoreText('PERSON_12', mappingOf([['⟦PERSON_1⟧', 'Jane Roe']], 'whiteSquare')), 'PERSON_12');
  for (const t of ['XPERSON_1', 'PERSON_1x', 'PERSON_1_', '_PERSON_1', 'aPERSON_1', 'éPERSON_1', 'PERSON_1é', '9PERSON_1']) {
    assert.equal(restoreText(t, W), t, t);
  }
});

test('lenient: unissued bare tokens stay verbatim and are not counted', () => {
  const r = createRestorer(W);
  assert.equal(stream(r, ['PERSON_2 UTF_8 SHA_256 PHONE_1 ', 'PERSON_1']), 'PERSON_2 UTF_8 SHA_256 PHONE_1 Jane Roe');
  assert.deepEqual(r.stats, { restored: 1, unknown: 0 });
});

test('lenient: a half-bracketed issued placeholder restores whole', () => {
  assert.equal(restoreText('a ⟦PERSON_1 b PERSON_1⟧ c', W), 'a Jane Roe b Jane Roe c');
});

test('lenient: bare form split across chunks is held until its boundary is known', () => {
  const r = createRestorer(W);
  assert.equal(r.push('Hi PERS'), 'Hi ');
  assert.equal(r.push('ON_1'), '', 'a complete bare token is held: the next char may be a digit');
  assert.equal(r.push('2!'), 'John Doe!');
  const r2 = createRestorer(W);
  assert.equal(stream(r2, ['Hi PERSON_1', ', bye']), 'Hi Jane Roe, bye');
  const r3 = createRestorer(W);
  assert.equal(r3.push('Hi PERSON_1'), 'Hi ');
  assert.equal(r3.flush(), 'Jane Roe', 'end of stream is a boundary');
  const r4 = createRestorer(W);
  assert.equal(stream(r4, ['XPERS', 'ON_1 y']), 'XPERSON_1 y', 'boundary context survives the chunk split');
});

test('json mode: bare placeholder in tool-call arguments restores to the escaped surface', () => {
  const m = mappingOf([['⟦PERSON_1⟧', 'Jane "JR" Roe']], 'whiteSquare');
  const r = createRestorer(m, { json: true });
  assert.deepEqual(JSON.parse(stream(r, ['{"name":"PER', 'SON_1","n2":"x\\nPERSON_1"}'])), { name: 'Jane "JR" Roe', n2: 'x\nJane "JR" Roe' });
});

test('json mode: \\u-escaped brackets (either hex case) restore to the escaped surface', () => {
  const m = mappingOf([['⟦PERSON_1⟧', 'Jane "JR" Roe']], 'whiteSquare');
  for (const ph of ['\\u27e6PERSON_1\\u27e7', '\\u27E6PERSON_1\\u27E7', '\\u27e6PERSON_1⟧', '⟦PERSON_1\\u27E7']) {
    const args = `{"name":"${ph}"}`;
    assert.deepEqual(JSON.parse(restoreText(args, m, { json: true })), { name: 'Jane "JR" Roe' }, ph);
    const r = createRestorer(m, { json: true });
    assert.deepEqual(JSON.parse(stream(r, [...args])), { name: 'Jane "JR" Roe' }, `${ph} char by char`);
    assert.deepEqual(r.stats, { restored: 1, unknown: 0 });
  }
  // an escaped placeholder that was never issued stays verbatim
  assert.equal(restoreText('"\\u27e6PERSON_9\\u27e7"', m, { json: true }), '"\\u27e6PERSON_9\\u27e7"');
});

test('text mode: \\u-escaped brackets are plain text, not a placeholder', () => {
  assert.equal(restoreText('\\u27e6PERSON_1\\u27e7', W), '\\u27e6PERSON_1\\u27e7');
});

// Property: for any chunking, streaming restore == whole-string restore.
function prng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

function checkChunkings(seed, atoms, mapping, opts) {
  const rand = prng(seed);
  for (let iter = 0; iter < 2000; iter++) {
    let s = '';
    const n = 1 + Math.floor(rand() * 12);
    for (let i = 0; i < n; i++) s += atoms[Math.floor(rand() * atoms.length)];
    const expected = restoreText(s, mapping, opts);
    const chunks = [];
    let i = 0;
    while (i < s.length) {
      const k = 1 + Math.floor(rand() * 5);
      chunks.push(s.slice(i, i + k));
      i += k;
    }
    const r = createRestorer(mapping, opts);
    assert.equal(stream(r, chunks), expected, `chunks=${JSON.stringify(chunks)}`);
  }
}

const COMMON_ATOMS = ['É', '😀', ' ', 'a', 'X', '_', '1', '2', '\n', 'PERSON_1', 'PERSON_12', 'PERSON_2', 'EMAIL_1', 'PERS', 'ON_1', 'PERSON_', '_1'];

test('property: any chunking of a string restores identically to restoreText', () => {
  checkChunkings(0xc0ffee, [...COMMON_ATOMS, '[PERSON_1]', '[PERSON_12]', '[EMAIL_1]', '[PERSON_2]', '[PERS', 'ON_1]', '[', ']', '[PERSON_', '_1]'], M);
});

test('property: chunking invariance holds for bare and \\u-escaped forms (text and json mode)', () => {
  const atoms = [...COMMON_ATOMS, '⟦PERSON_1⟧', '⟦', '⟧', '⟦PERS', '\\u27e6', '\\u27E7', '\\u27', 'e6', 'E7', '\\', '\\u27e6PERSON_12\\u27e7', '"'];
  checkChunkings(0xbadc0de, atoms, W);
  checkChunkings(0x5eed, atoms, W, { json: true });
});
