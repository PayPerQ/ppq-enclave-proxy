import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MESSAGES_DIALECT, requestsSafeguardsBeta } from '../src/messages.mjs';

const SG = [{ type: 'dangerous_tool_use', classifier_context: { v: 1, permission_mode: 'auto' } }];
const BODY = { model: 'anthropic/claude-opus-5.5', max_tokens: 100, messages: [{ role: 'user', content: 'hi' }], safeguards: SG };
const BETA = 'claude-code-20250219, dangerous-tool-use-2026-09-03,interleaved-thinking-2025-05-14';
const row = (provider, upstreamModelId) => ({ provider, upstreamModelId, serviceTier: '', supportsTools: true });

test('requestsSafeguardsBeta: matches a dangerous-tool-use-* token in a comma list', () => {
  assert.equal(requestsSafeguardsBeta(BETA), true);
  assert.equal(requestsSafeguardsBeta('dangerous-tool-use-2026-09-03'), true);
  for (const h of [undefined, '', 'claude-code-20250219', 'x-dangerous-tool-use-2026', ['dangerous-tool-use-2026-09-03']]) {
    assert.equal(requestsSafeguardsBeta(h), false, String(h));
  }
});

test('directProject: safeguards ride to Anthropic only with the beta; never to Fireworks or OpenAI', () => {
  const an = MESSAGES_DIALECT.directProject(BODY, row('anthropic', 'claude-opus-5-5'), { headers: { 'anthropic-beta': BETA } });
  assert.deepEqual(an.body.safeguards, SG);
  assert.equal(an.body.model, 'claude-opus-5-5');

  const noBeta = MESSAGES_DIALECT.directProject(BODY, row('anthropic', 'claude-opus-5-5'), { headers: {} });
  assert.equal('safeguards' in noBeta.body, false, 'without the beta Anthropic would 400 the field');
  const noHeaders = MESSAGES_DIALECT.directProject(BODY, row('anthropic', 'claude-opus-5-5'));
  assert.equal('safeguards' in noHeaders.body, false);

  const fw = MESSAGES_DIALECT.directProject(BODY, row('fireworks', 'accounts/fireworks/models/kimi-k3'), { headers: { 'anthropic-beta': BETA } });
  assert.equal('safeguards' in fw.body, false);
  const oa = MESSAGES_DIALECT.directProject(BODY, row('openai', 'gpt-5.5'), { headers: { 'anthropic-beta': BETA } });
  assert.equal(oa.skip, undefined);
  assert.equal(JSON.stringify(oa.body).includes('safeguards'), false);
  assert.equal(BODY.safeguards, SG, 'the caller body is not mutated (the OpenRouter fallback still sends it)');
});
