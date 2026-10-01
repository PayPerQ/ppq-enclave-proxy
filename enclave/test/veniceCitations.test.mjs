import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  VeniceCitationTranslator,
  countVeniceSearches,
  parseVeniceCitations,
  translateVeniceLine,
  MAX_LINE_CHARS,
} from '../src/veniceCitations.mjs';

// The frame Venice sends just before the usage frame when a search ran (hp
// probe, 2026-09-10): `choices: []` and the citations under a vendor key.
const citationFrame = (cites) =>
  `data: ${JSON.stringify({
    id: 'chatcmpl-1',
    object: 'chat.completion.chunk',
    created: 1790000000,
    model: 'venice-uncensored-1-2',
    choices: [],
    venice_parameters: { enable_web_search: 'on', web_search_citations: cites },
  })}`;
const delta = (text) => `data: ${JSON.stringify({ id: 'chatcmpl-1', choices: [{ index: 0, delta: { content: text } }] })}`;
const usage = `data: ${JSON.stringify({ id: 'chatcmpl-1', choices: [], usage: { prompt_tokens: 12, completion_tokens: 3 } })}`;
const CITES = [
  { title: 'Lighthouse', url: 'https://example.org/a', content: '<strong>hit</strong>', date: '2026-01-01' },
  { title: 'No link' },
  { url: 'https://example.org/b' },
];

const run = (text, { sse = true, size = 23 } = {}) => {
  const t = new VeniceCitationTranslator({ sse });
  const bytes = Buffer.from(text, 'utf8');
  const out = [];
  for (let i = 0; i < bytes.length; i += size) out.push(t.feed(bytes.subarray(i, i + size)));
  out.push(t.finish());
  return { out: Buffer.concat(out).toString('utf8'), searches: t.searches };
};

test('parse: a citation frame, an empty one, and everything else', () => {
  assert.equal(parseVeniceCitations(delta('hello')), null);
  assert.equal(parseVeniceCitations('data: [DONE]'), null);
  assert.deepEqual(parseVeniceCitations(citationFrame([])), []);
  assert.equal(parseVeniceCitations(citationFrame(CITES)).length, 3);
  // Model output that merely mentions the key is not a Venice frame.
  assert.equal(parseVeniceCitations(delta('the venice_parameters key')), null);
  assert.equal(parseVeniceCitations('data: {"venice_parameters": broken'), null);
  assert.equal(countVeniceSearches(null), 0);
  assert.equal(countVeniceSearches([]), 0);
  assert.equal(countVeniceSearches([{}]), 1);
});

test('translate: the frame becomes the annotations delta every PPQ client reads', () => {
  const line = translateVeniceLine(citationFrame(CITES));
  const parsed = JSON.parse(line.slice(6));
  assert.equal(parsed.id, 'chatcmpl-1');
  assert.equal(parsed.venice_parameters, undefined, 'the vendor key does not reach the client');
  assert.deepEqual(parsed.choices, [
    {
      index: 0,
      delta: {
        annotations: [
          { type: 'url_citation', url_citation: { url: 'https://example.org/a', title: 'Lighthouse', content: '<strong>hit</strong>' } },
          // The citation with no URL is unrenderable and dropped.
          { type: 'url_citation', url_citation: { url: 'https://example.org/b' } },
        ],
      },
      logprobs: null,
      finish_reason: null,
    },
  ]);
  // No citations (no search ran), or none with a URL: the frame is dropped.
  assert.equal(translateVeniceLine(citationFrame([])), null);
  assert.equal(translateVeniceLine(citationFrame([{ title: 'only a title' }])), null);
  // Anything else is returned as it came.
  assert.equal(translateVeniceLine(usage), usage);
});

test('stream: translated in place whatever the chunking, and the search is counted once', () => {
  const stream = [delta('Light'), delta('houses'), citationFrame(CITES), usage, 'data: [DONE]'].join('\n\n') + '\n\n';
  for (const size of [1, 7, 23, 64, 4096]) {
    const { out, searches } = run(stream, { size });
    assert.equal(searches, 1, `chunk size ${size}`);
    const frames = out.split('\n\n').filter(Boolean);
    assert.equal(frames.length, 5, `chunk size ${size}: ${out}`);
    assert.equal(frames[0], delta('Light'));
    assert.equal(frames[1], delta('houses'));
    assert.match(frames[2], /"annotations":\[\{"type":"url_citation"/);
    assert.doesNotMatch(out, /venice_parameters/);
    // The usage frame the settle is read from is untouched.
    assert.equal(frames[3], usage);
    assert.equal(frames[4], 'data: [DONE]');
  }
});

test('stream: no search ran — the empty frame is dropped whole and nothing is billed', () => {
  const stream = [delta('4'), citationFrame([]), usage, 'data: [DONE]'].join('\n\n') + '\n\n';
  const { out, searches } = run(stream);
  assert.equal(searches, 0);
  assert.equal(out, [delta('4'), usage, 'data: [DONE]'].join('\n\n') + '\n\n');
});

test('stream: a Venice turn with no citation frame passes through byte for byte', () => {
  const stream = [': keep-alive', delta('héllo → ✓'), usage, 'data: [DONE]'].join('\n\n') + '\n\n';
  for (const size of [1, 3, 50]) {
    const { out, searches } = run(stream, { size });
    assert.equal(out, stream);
    assert.equal(searches, 0);
  }
});

test('stream: a final line with no newline is still translated', () => {
  const { out, searches } = run(delta('x') + '\n\n' + citationFrame(CITES));
  assert.equal(searches, 1);
  assert.match(out, /"annotations"/);
});

test('stream: an over-long line is released raw instead of being held', () => {
  const big = `data: ${'x'.repeat(MAX_LINE_CHARS + 10)}`;
  const { out } = run(big + '\n\n', { size: 65536 });
  assert.equal(out, big + '\n\n');
});

test('non-streaming body: passed through untouched, but the search is still counted', () => {
  const body = JSON.stringify({
    id: 'chatcmpl-1',
    choices: [{ index: 0, message: { role: 'assistant', content: 'Lighthouses…', annotations: null } }],
    usage: { prompt_tokens: 12, completion_tokens: 3 },
    venice_parameters: { web_search_citations: CITES },
  });
  for (const size of [5, 31, 100000]) {
    const { out, searches } = run(body, { sse: false, size });
    assert.equal(out, body);
    assert.equal(searches, 1, `chunk size ${size}`);
  }
  const none = JSON.stringify({ choices: [{ message: { content: 'web_search_citations: [{' } }], venice_parameters: { web_search_citations: [] } });
  // An empty array, and the marker inside model text (escaped quotes), are not evidence.
  assert.equal(run(none, { sse: false }).searches, 0);
});
