// The authorize body's `reasoning_effort` (hp #1198): an enum read off each
// dialect's body, never content, and nothing at all when the body names none.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  REASONING_EFFORTS,
  normalizeReasoningEffort,
  chatReasoningEffort,
  responsesReasoningEffort,
  messagesReasoningEffort,
  dialectReasoningEffort,
} from '../src/reasoningEffort.mjs';

test('normalize: the six words exactly as written; everything else is undefined', () => {
  for (const e of REASONING_EFFORTS) assert.equal(normalizeReasoningEffort(e), e);
  // The body goes upstream unchanged, so a variant the provider would not
  // read as an effort must not be reported to hp as one.
  for (const bad of ['', ' high', 'HIGH', 'High ', 'none', 'ultra', 'constructor', 'high; x', 'a'.repeat(17), 3, true, null, undefined, {}, ['high']]) {
    assert.equal(normalizeReasoningEffort(bad), undefined, String(bad));
  }
});

test('chat: the reasoning object wins over a legacy reasoning_effort, budgets map through tiers', () => {
  assert.equal(chatReasoningEffort({ reasoning: { effort: 'high' }, reasoning_effort: 'low' }), 'high');
  assert.equal(chatReasoningEffort({ reasoning_effort: 'low' }), 'low');
  assert.equal(chatReasoningEffort({ reasoning_effort: 'Medium' }), undefined, 'exact vocabulary only');
  assert.equal(chatReasoningEffort({ reasoning: { max_tokens: 1024 } }), 'low');
  assert.equal(chatReasoningEffort({ reasoning: { max_tokens: 4096 } }), 'medium');
  assert.equal(chatReasoningEffort({ reasoning: { max_tokens: 30000 } }), 'high');
  assert.equal(chatReasoningEffort({ reasoning: { enabled: true } }), 'medium');
});

test('chat: nothing named, a disabled or malformed object, or an unknown word is undefined', () => {
  assert.equal(chatReasoningEffort({ messages: [] }), undefined);
  assert.equal(chatReasoningEffort({ reasoning: {} }), undefined);
  assert.equal(chatReasoningEffort({ reasoning: { enabled: false }, reasoning_effort: 'high' }), undefined);
  assert.equal(chatReasoningEffort({ reasoning: 'high' }), undefined);
  assert.equal(chatReasoningEffort({ reasoning: { effort: 'turbo' } }), undefined);
  assert.equal(chatReasoningEffort({ reasoning: { effort: 'x'.repeat(500) } }), undefined);
  assert.equal(chatReasoningEffort(null), undefined);
  assert.equal(chatReasoningEffort('x'), undefined);
});

test('responses: reasoning.effort only', () => {
  assert.equal(responsesReasoningEffort({ reasoning: { effort: 'xhigh' } }), 'xhigh');
  assert.equal(responsesReasoningEffort({ reasoning: { effort: 'minimal' } }), 'minimal');
  assert.equal(responsesReasoningEffort({ reasoning_effort: 'high' }), undefined);
  assert.equal(responsesReasoningEffort({ reasoning: { summary: 'auto' } }), undefined);
  assert.equal(responsesReasoningEffort(undefined), undefined);
});

test('messages: output_config.effort, else an enabled budget through the translator tiers', () => {
  assert.equal(messagesReasoningEffort({ output_config: { effort: 'max' } }), 'max');
  assert.equal(messagesReasoningEffort({ output_config: { effort: 'high' }, thinking: { type: 'enabled', budget_tokens: 1024 } }), 'high');
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled', budget_tokens: 1024 } }), 'low');
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled', budget_tokens: 8192 } }), 'medium');
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled', budget_tokens: 16000 } }), 'high');
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled', budget_tokens: 64000 } }), 'xhigh');
  // An invalid explicit effort does not fall through to the budget (the
  // translators bail on it, so no upstream sees an effort at all).
  assert.equal(messagesReasoningEffort({ output_config: { effort: 'turbo' }, thinking: { type: 'enabled', budget_tokens: 1024 } }), undefined);
  assert.equal(messagesReasoningEffort({ output_config: { effort: 'High' }, thinking: { type: 'enabled', budget_tokens: 1024 } }), undefined);
  assert.equal(messagesReasoningEffort({ output_config: {}, thinking: { type: 'enabled', budget_tokens: 1024 } }), 'low', 'no explicit effort: the budget speaks');
  assert.equal(messagesReasoningEffort({ thinking: { type: 'disabled' } }), undefined);
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled', budget_tokens: -5 } }), undefined);
  assert.equal(messagesReasoningEffort({ thinking: { type: 'enabled' } }), undefined);
  assert.equal(messagesReasoningEffort({ messages: [] }), undefined);
});

test('dialect dispatch by name; unknown dialects name nothing', () => {
  assert.equal(dialectReasoningEffort('messages', { output_config: { effort: 'low' } }), 'low');
  assert.equal(dialectReasoningEffort('responses', { reasoning: { effort: 'low' } }), 'low');
  assert.equal(dialectReasoningEffort('decisions', { reasoning: { effort: 'low' } }), undefined);
});
