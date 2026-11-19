import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WebSearchStats } from '../src/webSearchStats.mjs';
import { FirstTokenDetector } from '../src/firstToken.mjs';
import {
  createTraceRecorder,
  describeRequestShape,
  sanitizeRequestShape,
  sanitizeWebSearch,
} from '../src/trace.mjs';

const enc = (s) => new TextEncoder().encode(s);
const frame = (obj) => `data: ${JSON.stringify(obj)}\n\n`;
const cite = (url) => ({ type: 'url_citation', url_citation: { url, title: 't', content: 'secret page text' } });
const annot = (...urls) => frame({ choices: [{ index: 0, delta: { content: '', annotations: urls.map(cite) } }] });

test('counts distinct cited URLs and hosts, and the reported searches', () => {
  let first = 0;
  const s = new WebSearchStats({ onFirstCitation: () => first++ });
  s.feed(enc(': OPENROUTER PROCESSING\n\n'));
  s.feed(enc(annot('https://www.a.com/1', 'https://a.com/2')));
  const tail = annot('https://b.org/x', 'https://a.com/2');
  s.feed(enc(tail.slice(0, 20)));
  s.feed(enc(tail.slice(20)));
  s.feed(enc(frame({ choices: [{ delta: { content: 'answer' } }] })));
  s.feed(enc(frame({ choices: [], usage: { server_tool_use_details: { web_search_requests: 2 } } })));
  assert.deepEqual(s.finish(), { searches: 2, citations: 3, domains: 2 });
  assert.equal(first, 1);
});

test('a non-streaming body is read at finish(), message.annotations included', () => {
  const s = new WebSearchStats();
  s.feed(enc(JSON.stringify({ choices: [{ message: { content: 'x', annotations: [cite('https://c.net/')] } }] })));
  assert.deepEqual(s.finish(), { searches: undefined, citations: 1, domains: 1 });
});

test('no search: zero counts, no searches field', () => {
  const s = new WebSearchStats();
  s.feed(enc(frame({ choices: [{ delta: { content: 'hello' } }] })));
  assert.deepEqual(s.finish(), { searches: undefined, citations: 0, domains: 0 });
});

test('first-answer detector skips reasoning and waits for content', () => {
  const d = new FirstTokenDetector({ only: 'content' });
  assert.equal(d.feed(enc(frame({ choices: [{ delta: { reasoning: 'thinking' } }] }))), null);
  assert.equal(d.done, false);
  assert.equal(d.feed(enc(frame({ choices: [{ delta: { content: 'Hi' } }] }))), 'content');
  assert.equal(d.done, true);
});

test('describeRequestShape classifies how web search was asked for', () => {
  const ask = (body) => describeRequestShape({ model: 'a/b', ...body }).web_search;
  assert.equal(ask({ plugins: [{ id: 'web', max_results: 5 }] }), 'plugin');
  assert.equal(ask({ plugins: [{ id: 'web', enabled: false }] }), undefined);
  assert.equal(ask({ tools: [{ type: 'web_search' }] }), 'tool');
  assert.equal(ask({ tools: [{ type: 'openrouter:web_search' }] }), 'tool');
  assert.equal(ask({ tools: [{ type: 'web_search_20250305' }] }), 'dated_tool');
  assert.equal(ask({ web_search_options: {} }), 'options');
  assert.equal(ask({ model: 'a/b:online' }), 'suffix');
  assert.equal(ask({ tools: [{ type: 'function', function: { name: 'web_search' } }] }), undefined);
  assert.equal(describeRequestShape({ model: 'a/b', plugins: [{ id: 'web', max_results: 5 }] }).web_max_results, 5);
});

test('sanitizers drop out-of-vocabulary values', () => {
  assert.deepEqual(sanitizeRequestShape({ web_search: 'evil', web_max_results: 1e6 }).web_search, undefined);
  assert.equal(sanitizeRequestShape({ web_max_results: 1.5 }).web_max_results, undefined);
  assert.deepEqual(
    sanitizeWebSearch({ sent: 'exa', searches: 5000, citations: -1, domains: 2, url: 'https://x' }),
    { sent: 'exa', searches: 1000, domains: 2 },
  );
  assert.equal(sanitizeWebSearch({ sent: 'google' }), undefined);
});

test('trace carries t_first_answer_ms and the web_search block', () => {
  let t = 0;
  const rec = createTraceRecorder({ now: () => t });
  t = 900;
  rec.mark('firstCitation');
  t = 1500;
  rec.mark('firstAnswer');
  rec.setWebSearch({ sent: 'native', searches: 1, citations: 5, domains: 4 });
  const out = rec.build();
  assert.equal(out.t_first_answer_ms, 1500);
  assert.deepEqual(out.web_search, { sent: 'native', searches: 1, citations: 5, domains: 4, t_first_citation_ms: 900 });
  assert.equal(JSON.stringify(out).includes('secret'), false);
});

test('no web_search block when search was not requested', () => {
  const out = createTraceRecorder().build();
  assert.equal('web_search' in out, false);
  assert.equal('t_first_answer_ms' in out, false);
});
