import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  pseudonymize as pseudonymizeWith,
  mergeSpans,
  GRAMMARS,
  DEFAULT_GRAMMAR,
  PII_CLASSES,
} from '../src/pii/core.mjs';
import { restoreText } from '../src/pii/restore.mjs';

// Fixtures below are written in the `square` grammar; the default grammar has
// its own test ('default grammar is whiteSquare …').
const pseudonymize = (texts, spans, opts = {}) => pseudonymizeWith(texts, spans, { grammar: 'square', ...opts });

// All PII here is fictional (Jane Roe, example.com, documentation IBANs).

/** Span helper: locate `surface` (the nth occurrence) in `text`. */
function at(text, surface, cls, nth = 0) {
  let i = -1;
  for (let k = 0; k <= nth; k++) i = text.indexOf(surface, i + 1);
  assert.ok(i >= 0, `fixture: ${surface} not found`);
  return { start: i, end: i + surface.length, cls };
}

const surfacesOf = (mapping) => [...mapping.byPlaceholder.values()];

test('no spans: texts unchanged, empty mapping', () => {
  const texts = ['hello there', ''];
  const r = pseudonymize(texts, [[], []]);
  assert.deepEqual(r.texts, texts);
  assert.equal(r.mapping.byPlaceholder.size, 0);
});

test('a detected span is replaced by a placeholder and the mapping holds the surface', () => {
  const t = 'My name is Jane Roe, email jane.roe@example.com.';
  const r = pseudonymize([t], [[at(t, 'Jane Roe', 'PERSON'), at(t, 'jane.roe@example.com', 'EMAIL')]]);
  assert.equal(r.texts[0], 'My name is [PERSON_1], email [EMAIL_1].');
  assert.equal(r.mapping.byPlaceholder.get('[PERSON_1]'), 'Jane Roe');
  assert.equal(r.mapping.byPlaceholder.get('[EMAIL_1]'), 'jane.roe@example.com');
  assert.ok(!r.texts[0].includes('Jane Roe'));
  assert.ok(!r.texts[0].includes('example.com'));
});

test('PII-02: a repeated entity maps to one placeholder across all texts', () => {
  const a = 'Jane Roe called. Tell Jane Roe I said hi.';
  const b = 'Assistant: sure, I will tell jane  roe.'; // case/whitespace variant
  const r = pseudonymize(
    [a, b],
    [[at(a, 'Jane Roe', 'PERSON', 0), at(a, 'Jane Roe', 'PERSON', 1)], [at(b, 'jane  roe', 'PERSON')]],
  );
  assert.equal(r.texts[0], '[PERSON_1] called. Tell [PERSON_1] I said hi.');
  assert.equal(r.texts[1], 'Assistant: sure, I will tell [PERSON_1].');
  assert.equal(r.mapping.byPlaceholder.size, 1);
});

test('PII-02: distinct entities map to distinct placeholders', () => {
  const t = 'Jane Roe met John Doe at Acme Corp in Springfield.';
  const r = pseudonymize([t], [[
    at(t, 'Jane Roe', 'PERSON'), at(t, 'John Doe', 'PERSON'),
    at(t, 'Acme Corp', 'ORG'), at(t, 'Springfield', 'LOCATION'),
  ]]);
  assert.equal(r.texts[0], '[PERSON_1] met [PERSON_2] at [ORG_1] in [LOCATION_1].');
  assert.equal(new Set(r.mapping.byPlaceholder.keys()).size, 4);
});

test('same surface under two classes gets two placeholders (key is class + surface)', () => {
  const t = 'Jordan lives in Jordan.';
  const r = pseudonymize([t], [[at(t, 'Jordan', 'PERSON', 0), at(t, 'Jordan', 'LOCATION', 1)]]);
  assert.equal(r.texts[0], '[PERSON_1] lives in [LOCATION_1].');
});

test('spans are accepted in any order', () => {
  const t = 'Jane Roe and John Doe';
  const r = pseudonymize([t], [[at(t, 'John Doe', 'PERSON'), at(t, 'Jane Roe', 'PERSON')]]);
  // numbering follows text order, not detector order
  assert.equal(r.texts[0], '[PERSON_1] and [PERSON_2]');
});

test('overlap: the merged range covers every overlapping span; the longest decides the class', () => {
  const t = 'Write to Jane Roe Smith today';
  const r = pseudonymize([t], [[
    { start: 9, end: 17, cls: 'PERSON' },  // "Jane Roe"
    { start: 14, end: 23, cls: 'ORG' },    // "Roe Smith" (shorter than the union, longer than PERSON? 9 vs 8)
  ]]);
  // union = "Jane Roe Smith"; ORG span (9 chars) is longer than PERSON (8)
  assert.equal(r.texts[0], 'Write to [ORG_1] today');
  assert.equal(r.mapping.byPlaceholder.get('[ORG_1]'), 'Jane Roe Smith');
});

test('overlap: a contained span is absorbed by the longer one', () => {
  const t = 'at 42 Example Street, Springfield ok';
  const addr = at(t, '42 Example Street, Springfield', 'ADDRESS');
  const loc = at(t, 'Springfield', 'LOCATION');
  const r = pseudonymize([t], [[loc, addr]]);
  assert.equal(r.texts[0], 'at [ADDRESS_1] ok');
  assert.deepEqual(surfacesOf(r.mapping), ['42 Example Street, Springfield']);
});

test('adjacent (touching) spans stay separate', () => {
  const t = 'JaneRoe';
  const r = pseudonymize([t], [[{ start: 0, end: 4, cls: 'PERSON' }, { start: 4, end: 7, cls: 'PERSON' }]]);
  assert.equal(r.texts[0], '[PERSON_1][PERSON_2]');
});

test('mergeSpans: equal-length tie keeps the earliest span class', () => {
  const merged = mergeSpans('abcdefgh', [{ start: 0, end: 4, cls: 'ORG' }, { start: 2, end: 6, cls: 'PERSON' }]);
  assert.deepEqual(merged, [{ start: 0, end: 6, cls: 'ORG' }]);
});

test('zero-length spans are ignored', () => {
  const t = 'nothing here';
  const r = pseudonymize([t], [[{ start: 3, end: 3, cls: 'PERSON' }]]);
  assert.equal(r.texts[0], t);
  assert.equal(r.mapping.byPlaceholder.size, 0);
});

test('whitespace-only spans are not replaced', () => {
  const t = 'a   b';
  const r = pseudonymize([t], [[{ start: 1, end: 4, cls: 'PERSON' }]]);
  assert.equal(r.texts[0], t);
});

test('collision safety: input already containing the grammar never gets that placeholder issued', () => {
  const t = 'Literal [PERSON_1] and [EMAIL_2] in my text; real name Jane Roe, mail jane@example.com';
  const r = pseudonymize([t], [[at(t, 'Jane Roe', 'PERSON'), at(t, 'jane@example.com', 'EMAIL')]]);
  // the user's own literal tokens survive untouched and are NOT in the mapping
  assert.ok(r.texts[0].startsWith('Literal [PERSON_1] and [EMAIL_2] in my text;'));
  assert.ok(!r.mapping.byPlaceholder.has('[PERSON_1]'));
  const issued = [...r.mapping.byPlaceholder.keys()];
  assert.equal(issued.length, 2);
  for (const ph of issued) assert.equal(t.split(ph).length, 1, `${ph} collides with input`);
  assert.ok(r.texts[0].endsWith('real name [PERSON_2], mail [EMAIL_1]'));
});

test('collision safety also covers bare CLASS_n literals (the restorer is lenient)', () => {
  const t = 'Variable PERSON_1 and EMAIL_1x and \\u27e6PERSON_2\\u27e7; real name Jane Roe';
  const r = pseudonymize([t], [[at(t, 'Jane Roe', 'PERSON')]], { grammar: 'whiteSquare' });
  // PERSON_1 and PERSON_2 are taken by the user's own text (bare or escaped)
  assert.ok(r.texts[0].endsWith('real name ⟦PERSON_3⟧'));
  assert.deepEqual([...r.mapping.byPlaceholder.keys()], ['⟦PERSON_3⟧']);
});

test('collision safety applies across texts (a literal in text B blocks the index in text A)', () => {
  const a = 'Jane Roe';
  const b = 'see [PERSON_1]';
  const r = pseudonymize([a, b], [[at(a, 'Jane Roe', 'PERSON')], []]);
  assert.equal(r.texts[0], '[PERSON_2]');
  assert.equal(r.texts[1], 'see [PERSON_1]');
});

test('each grammar produces its own delimiters', () => {
  const t = 'Hi Jane Roe';
  const spans = [[at(t, 'Jane Roe', 'PERSON')]];
  assert.equal(pseudonymize([t], spans, { grammar: 'square' }).texts[0], 'Hi [PERSON_1]');
  assert.equal(pseudonymize([t], spans, { grammar: 'whiteSquare' }).texts[0], 'Hi ⟦PERSON_1⟧');
  assert.equal(pseudonymize([t], spans, { grammar: 'angle' }).texts[0], 'Hi <PERSON_1>');
  assert.equal(pseudonymizeWith([t], spans).mapping.grammar, GRAMMARS[DEFAULT_GRAMMAR]);
});

test('default grammar is whiteSquare (picked by the live preservation eval) and round-trips', () => {
  assert.equal(DEFAULT_GRAMMAR, 'whiteSquare');
  const t = 'Mail jane.roe@example.com, Jane Roe';
  const r = pseudonymizeWith([t], [[at(t, 'jane.roe@example.com', 'EMAIL'), at(t, 'Jane Roe', 'PERSON')]]);
  assert.equal(r.texts[0], 'Mail ⟦EMAIL_1⟧, ⟦PERSON_1⟧');
  assert.equal(restoreText(r.texts[0], r.mapping), t);
});

test('a literal in another grammar still reserves its index (lenient restore would read it as bare)', () => {
  const t = 'Tag <PERSON_1> and Jane Roe';
  const r = pseudonymize([t], [[at(t, 'Jane Roe', 'PERSON')]], { grammar: 'square' });
  assert.equal(r.texts[0], 'Tag <PERSON_1> and [PERSON_2]');
});

test('unicode: offsets are UTF-16 indices; emoji and accents before a span are handled', () => {
  const t = '👋🏽 Olá, sou a Joana Mendonça — 📧 joana@example.com';
  const r = pseudonymize([t], [[at(t, 'Joana Mendonça', 'PERSON'), at(t, 'joana@example.com', 'EMAIL')]]);
  assert.equal(r.texts[0], '👋🏽 Olá, sou a [PERSON_1] — 📧 [EMAIL_1]');
  assert.equal(r.mapping.byPlaceholder.get('[PERSON_1]'), 'Joana Mendonça');
});

test('unicode: NFC and NFD spellings of one name are the same entity', () => {
  const nfc = 'Zoë Roe'.normalize('NFC');
  const nfd = 'Zoë Roe'.normalize('NFD');
  assert.notEqual(nfc, nfd);
  const r = pseudonymize([nfc, nfd], [[{ start: 0, end: nfc.length, cls: 'PERSON' }], [{ start: 0, end: nfd.length, cls: 'PERSON' }]]);
  assert.deepEqual(r.texts, ['[PERSON_1]', '[PERSON_1]']);
});

test('unicode: a span boundary inside a surrogate pair is rejected (fail closed)', () => {
  const t = 'x😀y';
  assert.throws(() => pseudonymize([t], [[{ start: 2, end: 4, cls: 'PERSON' }]]), { code: 'pii_invalid_span' });
});

test('invalid spans fail closed and the error never echoes the text', () => {
  const t = 'Jane Roe secret';
  const bad = [
    { start: -1, end: 2, cls: 'PERSON' },
    { start: 0, end: 99, cls: 'PERSON' },
    { start: 5, end: 2, cls: 'PERSON' },
    { start: 0.5, end: 2, cls: 'PERSON' },
    { start: 0, end: 4, cls: 'NOT_A_CLASS' },
  ];
  for (const s of bad) {
    assert.throws(() => pseudonymize([t], [[s]]), (e) => {
      assert.equal(e.code, 'pii_invalid_span');
      assert.ok(!e.message.includes('Jane'));
      return true;
    });
  }
  assert.throws(() => pseudonymize([t], []), { code: 'pii_invalid_input' });
  assert.throws(() => pseudonymize([t], [[]], { grammar: 'nope' }), { code: 'pii_invalid_input' });
});

test('input arrays are not mutated', () => {
  const texts = ['Jane Roe'];
  const spans = [[{ start: 0, end: 8, cls: 'PERSON' }]];
  const copy = JSON.parse(JSON.stringify(spans));
  pseudonymize(texts, spans);
  assert.deepEqual(texts, ['Jane Roe']);
  assert.deepEqual(spans, copy);
});

test('every class yields a placeholder the grammar recognises', () => {
  for (const cls of PII_CLASSES) {
    const r = pseudonymize(['value'], [[{ start: 0, end: 5, cls }]]);
    assert.equal(r.texts[0], `[${cls}_1]`);
  }
});
