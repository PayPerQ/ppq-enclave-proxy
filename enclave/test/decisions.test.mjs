import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DECISIONS_ENDPOINT,
  DECISIONS_UPSTREAM_PATH,
  MAX_QUESTIONS,
  MAX_REQUEST_CHARS,
  MAX_STATE_CHARS,
  decisionsUsage,
  measureDecisionsInput,
  validateDecisionsRequest,
} from '../src/decisions.mjs';

const noul = { type: 'noul', instructions: 'Is this a billing issue?' };
const M = 'typesafe/jev-1.13';
const ok = (b) => {
  const r = validateDecisionsRequest(b);
  assert.equal(r.kind, 'ok', JSON.stringify(r));
  return r.value;
};
const bad = (b) => {
  const r = validateDecisionsRequest(b);
  assert.equal(r.kind, 'invalid');
  return r.error;
};

test('validator: accepts what OpenRouter accepts (JSON instructions, noul criteria, null choice descriptions, single labels)', () => {
  ok({ model: M, state: 'x', questions: { q: noul } });
  assert.equal(ok({ model: M, state: '', questions: { q: noul } }).state, '');
  ok({ model: M, state: [{ role: 'user', content: 'hi' }], questions: { q: { type: 'noul', instructions: { ask: 1 } } } });
  ok({ model: M, state: 'x', questions: { q: { ...noul, criteria: { true: 'yes', false: 'no' } } } });
  ok({
    model: M,
    state: { a: 1 },
    questions: {
      c: { type: 'choice', instructions: 'i', criteria: { a: { d: 1 }, b: null } },
      s: { type: 'score', instructions: ['a'], criteria: [{ l: 1 }, 'high'] },
      one: { type: 'score', instructions: 'i', criteria: ['only'] },
    },
  });
});

test('validator: refuses what OpenRouter refuses (null state, missing/null instructions, null noul criteria, null score entry)', () => {
  assert.equal(bad({ model: M, state: null, questions: { q: noul } }).field, 'state');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'noul' } } }).field, 'questions.q.instructions');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'noul', instructions: null } } }).field, 'questions.q.instructions');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { ...noul, criteria: null } } }).field, 'questions.q.criteria');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'score', instructions: 'i', criteria: [null, 'b'] } } }).field, 'questions.q.criteria');
});

test('validator: forwards only model/state/questions; question extras survive', () => {
  const v = ok({ model: M, state: 'x', questions: { q: { ...noul, examples: [1] } }, stream: true, provider: {} });
  assert.deepEqual(Object.keys(v).sort(), ['model', 'questions', 'state']);
  assert.deepEqual(v.questions.q.examples, [1]);
});

test('validator: refusals name the field, never a value', () => {
  assert.equal(bad('nope').field, 'body');
  assert.equal(bad({ state: 'x', questions: { q: noul } }).field, 'model');
  assert.equal(bad({ model: M, questions: { q: noul } }).field, 'state');
  assert.equal(bad({ model: M, state: 42, questions: { q: noul } }).field, 'state');
  assert.equal(bad({ model: M, state: 'x'.repeat(MAX_STATE_CHARS + 1), questions: { q: noul } }).field, 'state');
  assert.equal(bad({ model: M, state: 'x', questions: {} }).field, 'questions');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { ...noul, notes: 'x'.repeat(MAX_REQUEST_CHARS) } } }).field, 'questions');
  const many = Object.fromEntries(Array.from({ length: MAX_QUESTIONS + 1 }, (_, i) => [`q${i}`, noul]));
  assert.equal(bad({ model: M, state: 'x', questions: many }).field, 'questions');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'yesno' } } }).field, 'questions.q.type');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'noul', instructions: 7 } } }).field, 'questions.q.instructions');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'choice', instructions: 'i' } } }).field, 'questions.q.criteria');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'choice', instructions: 'i', criteria: { a: 1 } } } }).field, 'questions.q.criteria.a');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { type: 'score', instructions: 'i', criteria: [] } } }).field, 'questions.q.criteria');
  assert.equal(bad({ model: M, state: 'x', questions: { q: { ...noul, criteria: 'yes' } } }).field, 'questions.q.criteria');
  const secret = 'my password is hunter2';
  const e = bad({ model: M, state: secret, questions: { q: { type: 'choice', instructions: 'i', criteria: { [secret]: 1 } } } });
  // The field path carries the caller's option KEY (a schema position, as the
  // upstream's own errors do); the message never carries a value.
  assert.ok(!e.message.includes('hunter2'));
});

test('measure: counts the serialized state+questions, marks the endpoint, never a message', async () => {
  const req = ok({ model: M, state: 'The customer was charged twice.', questions: { q: noul } });
  const m = await measureDecisionsInput(req);
  assert.equal(m.endpoint, DECISIONS_ENDPOINT);
  assert.equal(m.message_count, 0);
  assert.equal(m.input_bytes, Buffer.byteLength(JSON.stringify({ state: req.state, questions: req.questions })));
  assert.ok(Number.isInteger(m.input_tokens_o200k) && m.input_tokens_o200k > 5);
  assert.equal(DECISIONS_UPSTREAM_PATH, '/api/alpha/decisions');
});

test('usage: reads the inline invoice, keeps a gen- id, zeros on garbage', () => {
  const u = decisionsUsage({
    model: 'typesafe/jev-1.13-20260917',
    answers: {},
    usage: { input_tokens: 404, output_tokens: 72, cost: 0.000016968 },
    id: 'gen-dec-1789982006-pw4c',
  });
  assert.deepEqual(u, {
    inputTokens: 404,
    outputTokens: 72,
    totalCost: 0.000016968,
    generationId: 'gen-dec-1789982006-pw4c',
    servedModel: 'typesafe/jev-1.13-20260917',
  });
  assert.deepEqual(decisionsUsage(null), { inputTokens: 0, outputTokens: 0, totalCost: 0, generationId: '', servedModel: undefined });
  assert.equal(decisionsUsage({ usage: { cost: -1, input_tokens: 'x' }, id: 'nope' }).totalCost, 0);
  assert.equal(decisionsUsage({ id: 'nope' }).generationId, '');
});
