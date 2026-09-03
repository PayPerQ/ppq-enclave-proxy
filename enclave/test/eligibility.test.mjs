import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateDirectEligibility,
  projectAllowedFields,
  refusesUnauthorizedFree,
} from '../src/eligibility.mjs';

// ── free aliases must fail closed without hp's directive ────────────────────
// The dangerous case is NOT a missing model: hp initialises resolved_model to
// the raw slug and only overwrites it on success, so a resolution failure looks
// exactly like a success to the enclave. `openrouter/free` is a real OpenRouter
// slug, so the request would be SERVED on the paid path with no free strip —
// keeping any `web` plugin the caller attached and billing PPQ for it on a
// request that must cost $0.

test('free alias without the is_free directive is refused', () => {
  for (const m of ['ppq/free', 'openrouter/free']) {
    assert.equal(refusesUnauthorizedFree(m, false), true, m);
    assert.equal(refusesUnauthorizedFree(m, undefined), true, m);
  }
});

// Anything not exactly `true` is treated as absent — an older hp that omits the
// field, or a truthy-but-wrong value, must not buy its way onto the paid path.
test('only a literal true satisfies the free directive', () => {
  for (const v of ['true', 1, {}, null, 'yes']) {
    assert.equal(refusesUnauthorizedFree('openrouter/free', v), true, String(v));
  }
  assert.equal(refusesUnauthorizedFree('openrouter/free', true), false);
});

test('a properly authorized free request proceeds', () => {
  assert.equal(refusesUnauthorizedFree('ppq/free', true), false);
});

// Blast radius: the guard must not touch paid models, including slugs that
// merely look free. Those are hp's to bill normally — the exact confusion the
// old `:free` regex caused.
test('paid models are never refused by the free guard', () => {
  for (const m of [
    'moonshotai/kimi-k3',
    'cohere/north-mini-code:free',
    'some/model-free',
    '',
  ]) {
    assert.equal(refusesUnauthorizedFree(m, false), false, m);
    assert.equal(refusesUnauthorizedFree(m, true), false, m);
  }
});

const CC = '/chat/completions';
function row(o = {}) {
  return {
    provider: 'fireworks',
    upstreamModelId: 'accounts/fireworks/models/kimi-k3',
    serviceTier: '',
    supportsTools: true,
    enabled: true,
    enabledOverride: null,
    ...o,
  };
}
const msgs = [{ role: 'user', content: 'hi' }];
const evalE = (payload, o = {}) =>
  evaluateDirectEligibility({ payload, path: CC, modelSuffixes: [], row: row(), ...o });

// ── evaluateDirectEligibility ────────────────────────────────────────────────

test('eligible: plain chat request with a valid row', () => {
  assert.deepEqual(evalE({ model: 'moonshotai/kimi-k3', messages: msgs }), { eligible: true });
});

test('bails on an unsupported top-level field, naming it', () => {
  const r = evalE({ model: 'moonshotai/kimi-k3', messages: msgs, provider: { sort: 'price' } });
  assert.equal(r.eligible, false);
  assert.equal(r.reason, 'unsupported_field');
  assert.equal(r.offendingField, 'provider');
});

test('web search forces OpenRouter — both the plugin and server-tool forms bail', () => {
  // Plugin form.
  assert.equal(
    evalE({ model: 'moonshotai/kimi-k3', messages: msgs, plugins: [{ id: 'web' }] }).reason,
    'web_search_requires_openrouter',
  );
  // Server-tool form — the gap that reached Fireworks: `tools` is allowlisted and
  // kimi-k3 supports tools, so without the explicit check this served WITHOUT search.
  assert.equal(
    evalE({
      model: 'moonshotai/kimi-k3',
      messages: msgs,
      tools: [{ type: 'openrouter:web_search', parameters: { engine: 'exa' } }],
    }).reason,
    'web_search_requires_openrouter',
  );
  // An ordinary function tool is still eligible.
  assert.equal(
    evalE({ model: 'moonshotai/kimi-k3', messages: msgs, tools: [{ type: 'function', function: { name: 'f' } }] }).eligible,
    true,
  );
});

test('IGNORED_FIELDS (session_id/query_source) do not bail', () => {
  assert.deepEqual(
    evalE({ model: 'moonshotai/kimi-k3', messages: msgs, session_id: 's', query_source: 'ui' }),
    { eligible: true },
  );
});

test('bails free / router / suffix with distinct reasons', () => {
  assert.equal(evalE({ model: 'ppq/free', messages: msgs }).reason, 'free_model');
  assert.equal(evalE({ model: 'openrouter/auto', messages: msgs }).reason, 'auto_router_model');
  assert.equal(evalE({ model: 'moonshotai/kimi-k3', messages: msgs }, { modelSuffixes: ['nitro'] }).reason, 'or_routing_suffix');
});

test('zdr: served direct on a ZDR provider row, bails otherwise', () => {
  const zdrPayload = { model: 'moonshotai/kimi-k3', messages: msgs, provider: { zdr: true } };
  // Fireworks is zero-data-retention (ZDR_DIRECT_PROVIDERS), so the
  // Private-models UI's zdr-only provider object no longer forfeits direct.
  assert.deepEqual(evalE(zdrPayload), { eligible: true });
  // A non-ZDR provider row bails so OpenRouter enforces ZDR routing.
  assert.equal(evalE(zdrPayload, { row: row({ provider: 'anthropic' }) }).reason, 'zdr_requested');
  // No row: still the shape reason, not model_not_in_catalog.
  assert.equal(evalE(zdrPayload, { row: undefined }).reason, 'zdr_requested');
  // provider carrying routing directives alongside zdr keeps bailing.
  const mixed = evalE({ ...zdrPayload, provider: { zdr: true, sort: 'price' } });
  assert.equal(mixed.reason, 'unsupported_field');
  assert.equal(mixed.offendingField, 'provider');
  // The zdr-only provider object is never forwarded upstream.
  assert.equal('provider' in projectAllowedFields(zdrPayload, row()), false);
});

test('admits a string message reasoning echo; bails any other shape', () => {
  // The OpenCode/Vercel-AI-SDK echo — admitted since the reasoning
  // canonicalization build (projection renames or drops it).
  assert.deepEqual(
    evalE({ model: 'moonshotai/kimi-k3', messages: [{ role: 'assistant', content: 'x', reasoning: 'chain' }] }),
    { eligible: true },
  );
  const r = evalE({
    model: 'moonshotai/kimi-k3',
    messages: [{ role: 'assistant', content: 'x', reasoning: { text: 'structured' } }],
  });
  assert.equal(r.reason, 'unsupported_message_field');
  assert.equal(r.offendingField, 'reasoning');
  // …and only on ASSISTANT turns — a user-injected echo is a shape nobody
  // documented and must keep bailing.
  const user = evalE({
    model: 'moonshotai/kimi-k3',
    messages: [{ role: 'user', content: 'x', reasoning: 'injected' }],
  });
  assert.equal(user.reason, 'unsupported_message_field');
  assert.equal(user.offendingField, 'reasoning');
});

test('translates the OpenRouter reasoning object; bails only unhonorable shapes', () => {
  // Honorable shapes are eligible…
  for (const reasoning of [{ effort: 'high' }, { max_tokens: 4096 }, { enabled: true }, {}, { exclude: true }]) {
    assert.deepEqual(evalE({ model: 'moonshotai/kimi-k3', messages: msgs, reasoning }), { eligible: true });
  }
  // …and project to the canonical reasoning_effort (object beats legacy field).
  const project = (reasoning, extra = {}) =>
    projectAllowedFields({ model: 'm', messages: msgs, stream: true, reasoning, ...extra }, row());
  assert.equal(project({ effort: 'high' }).reasoning_effort, 'high');
  assert.equal(project({ max_tokens: 1024 }).reasoning_effort, 'low');
  assert.equal(project({ max_tokens: 8192 }).reasoning_effort, 'medium');
  assert.equal(project({ max_tokens: 65536 }).reasoning_effort, 'high'); // capped — xhigh is Anthropic-only
  assert.equal(project({ enabled: true }).reasoning_effort, 'medium');
  assert.equal(project({ effort: 'low' }, { reasoning_effort: 'high' }).reasoning_effort, 'low');
  assert.equal('reasoning_effort' in project({ exclude: true }), false);
  // Unhonorable shapes bail with the member named.
  for (const [reasoning, member] of [
    [{ effort: 'high', custom_knob: 1 }, 'reasoning.custom_knob'],
    [{ enabled: false }, 'reasoning.enabled'], // explicit off — OpenRouter honors it
    [{ max_tokens: '4096' }, 'reasoning.max_tokens'],
    [{ max_tokens: 0.5 }, 'reasoning.max_tokens'], // OR contract: positive integer
    ['high', 'reasoning'],
  ]) {
    const r = evalE({ model: 'moonshotai/kimi-k3', messages: msgs, reasoning });
    assert.equal(r.reason, 'unmappable_field');
    assert.equal(r.offendingField, member);
  }
});

test('message reasoning echoes: reasoning_content rename on fireworks, drop elsewhere, never mutate', () => {
  const messages = () => [
    { role: 'user', content: 'fix' },
    { role: 'assistant', content: 'done', reasoning: 'thinking…', reasoning_details: [{ t: 1 }] },
  ];
  const payload = { model: 'm', messages: messages(), stream: true };
  const fw = projectAllowedFields(payload, row());
  assert.deepEqual(fw.messages[1], { role: 'assistant', content: 'done', reasoning_content: 'thinking…' });
  const br = projectAllowedFields(payload, row({ provider: 'bedrock' }));
  assert.deepEqual(br.messages[1], { role: 'assistant', content: 'done' });
  // The client payload is untouched (the OpenRouter fallback still sends it).
  assert.deepEqual(payload.messages, messages());
});

test('allows reasoning_content on a message (the load-bearing distinction)', () => {
  assert.deepEqual(
    evalE({ model: 'moonshotai/kimi-k3', messages: [{ role: 'assistant', content: 'x', reasoning_content: 'c' }] }),
    { eligible: true },
  );
});

test('bails non-text (image) content', () => {
  const r = evalE({
    model: 'moonshotai/kimi-k3',
    messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'x' } }] }],
  });
  assert.equal(r.reason, 'non_text_content');
});

test('bails json_schema response_format; text/json_object pass', () => {
  assert.equal(evalE({ model: 'm', messages: msgs, response_format: { type: 'json_schema' } }).reason, 'response_format_unsupported');
  assert.deepEqual(evalE({ model: 'moonshotai/kimi-k3', messages: msgs, response_format: { type: 'json_object' } }), { eligible: true });
});

test('bails when no catalog row / disabled row', () => {
  assert.equal(evaluateDirectEligibility({ payload: { model: 'm', messages: msgs }, path: CC, modelSuffixes: [], row: undefined }).reason, 'model_not_in_catalog');
  assert.equal(evalE({ model: 'm', messages: msgs }, { row: row({ enabled: false, enabledOverride: null }) }).reason, 'model_disabled');
});

test('bails tools when the row does not support them', () => {
  const r = evalE(
    { model: 'm', messages: msgs, tools: [{ type: 'function', function: { name: 'f' } }] },
    { row: row({ supportsTools: false }) },
  );
  assert.equal(r.reason, 'tools_unsupported_by_model');
});

test('non-chat path bails', () => {
  assert.equal(evaluateDirectEligibility({ payload: { model: 'm', messages: msgs }, path: '/responses', modelSuffixes: [], row: row() }).reason, 'endpoint_not_chat_completions');
});

// ── projectAllowedFields ─────────────────────────────────────────────────────

test('projects only allowlisted fields; model from the row; usage pinned on stream', () => {
  const body = projectAllowedFields(
    { model: 'moonshotai/kimi-k3', messages: msgs, temperature: 0.5, stream: true, provider: { sort: 'x' }, session_id: 's' },
    row({ upstreamModelId: 'accounts/fireworks/models/kimi-k3', serviceTier: '' }),
  );
  assert.equal(body.model, 'accounts/fireworks/models/kimi-k3'); // from row, not payload
  assert.equal(body.temperature, 0.5);
  assert.deepEqual(body.stream_options, { include_usage: true });
  assert.equal('provider' in body, false); // OpenRouter-only stripped
  assert.equal('session_id' in body, false); // PPQ-internal not forwarded
});

test('projectAllowedFields sets service_tier from a priority row; drops stream_options when not streaming', () => {
  const body = projectAllowedFields(
    { model: 'm', messages: msgs, stream: false, stream_options: { include_usage: true } },
    row({ serviceTier: 'priority' }),
  );
  assert.equal(body.service_tier, 'priority');
  assert.equal('stream_options' in body, false);
});

// ── image-input gate (Vertex phase 1; hp keeps a mirrored suite) ────────────

const IMG = `data:image/png;base64,${'A'.repeat(64)}`;
const imgMsg = (url, role = 'user') => ({
  role,
  content: [
    { type: 'text', text: 'what is this?' },
    { type: 'image_url', image_url: { url } },
  ],
});
const vertexRow = (o = {}) =>
  row({ provider: 'vertex', upstreamModelId: 'google/gemini-2.5-flash', supportsImageInput: true, ...o });

test('admits data-URI images on a vertex row that advertises image support', () => {
  assert.deepEqual(
    evalE({ model: 'google/gemini-2.5-flash', messages: [imgMsg(IMG)] }, { row: vertexRow() }),
    { eligible: true },
  );
});

test('IMAGE_DIRECT_PROVIDERS is default-closed: a vision-claiming fireworks row still bails', () => {
  const r = evalE(
    { model: 'moonshotai/kimi-k3', messages: [imgMsg(IMG)] },
    { row: row({ supportsImageInput: true }) },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('bails when the vertex row does not advertise image support', () => {
  const r = evalE(
    { model: 'google/gemini-2.5-flash', messages: [imgMsg(IMG)] },
    { row: vertexRow({ supportsImageInput: false }) },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('https image URLs keep bailing — OpenRouter inlines them, the enclave must not fetch', () => {
  const r = evalE(
    { model: 'google/gemini-2.5-flash', messages: [imgMsg('https://example.com/cat.png')] },
    { row: vertexRow() },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('oversized data URIs and assistant-turn images bail', () => {
  const huge = `data:image/png;base64,${'A'.repeat(7 * 1024 * 1024 + 1)}`;
  assert.equal(
    evalE({ model: 'google/gemini-2.5-flash', messages: [imgMsg(huge)] }, { row: vertexRow() }).reason,
    'non_text_content',
  );
  assert.equal(
    evalE(
      { model: 'google/gemini-2.5-flash', messages: [{ role: 'user', content: 'hi' }, imgMsg(IMG, 'assistant')] },
      { row: vertexRow() },
    ).reason,
    'non_text_content',
  );
});

test('the AGGREGATE image cap bails individually-valid images (spanning messages too)', () => {
  const fiveMb = `data:image/png;base64,${'A'.repeat(5 * 1024 * 1024)}`;
  const nImages = (n) => ({
    role: 'user',
    content: Array.from({ length: n }, () => ({ type: 'image_url', image_url: { url: fiveMb } })),
  });
  assert.deepEqual(
    evalE({ model: 'google/gemini-2.5-flash', messages: [nImages(2)] }, { row: vertexRow() }),
    { eligible: true },
  );
  assert.equal(
    evalE({ model: 'google/gemini-2.5-flash', messages: [nImages(3)] }, { row: vertexRow() }).reason,
    'non_text_content',
  );
  assert.equal(
    evalE({ model: 'google/gemini-2.5-flash', messages: [nImages(2), nImages(1)] }, { row: vertexRow() }).reason,
    'non_text_content',
  );
});

test('non-base64 encodings and uncleared media types bail; the cleared set passes', () => {
  for (const url of [
    'data:image/svg+xml,<svg onload="x"/>',
    'data:image/png,rawbytes',
    'data:image/tiff;base64,QUJD',
    'data:text/html;base64,QUJD',
  ]) {
    assert.equal(
      evalE({ model: 'google/gemini-2.5-flash', messages: [imgMsg(url)] }, { row: vertexRow() }).reason,
      'non_text_content',
      url,
    );
  }
  for (const type of ['png', 'jpeg', 'webp', 'heic', 'heif']) {
    assert.deepEqual(
      evalE(
        { model: 'google/gemini-2.5-flash', messages: [imgMsg(`data:image/${type};base64,QUJD`)] },
        { row: vertexRow() },
      ),
      { eligible: true },
      type,
    );
  }
});

test('an image at EXACTLY 5MB decoded passes — padding chars are not data', () => {
  // 5,242,880 decoded bytes encode to 6,990,508 base64 chars incl. one '='.
  const data = 'A'.repeat(6_990_507) + '=';
  const block = { type: 'image', source: { type: 'base64', media_type: 'image/png', data } };
  const r = evaluateDirectEligibility({
    payload: { model: 'anthropic/claude-sonnet-4.6', max_tokens: 100, messages: [{ role: 'user', content: [block] }] },
    path: '/messages',
    modelSuffixes: [],
    row: row({ provider: 'anthropic', supportsImageInput: true }),
  });
  assert.deepEqual(r, { eligible: true });
  const over = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'A'.repeat(6_990_512) } };
  const r2 = evaluateDirectEligibility({
    payload: { model: 'anthropic/claude-sonnet-4.6', max_tokens: 100, messages: [{ role: 'user', content: [over] }] },
    path: '/messages',
    modelSuffixes: [],
    row: row({ provider: 'anthropic', supportsImageInput: true }),
  });
  assert.equal(r2.reason, 'non_text_content');
});

test('malformed base64 is never admitted (both dialects)', () => {
  for (const payload of ['A', 'QUJ$', 'QU=J', 'A===', '']) {
    const chat = evaluateDirectEligibility({
      payload: { model: 'anthropic/claude-sonnet-4.6', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:image/png;base64,${payload}` } }] }] },
      path: CC, modelSuffixes: [],
      row: row({ provider: 'anthropic', supportsImageInput: true }),
    });
    assert.equal(chat.reason, 'non_text_content', 'chat:' + JSON.stringify(payload));
    const native = evaluateDirectEligibility({
      payload: { model: 'anthropic/claude-sonnet-4.6', max_tokens: 100, messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: payload } }] }] },
      path: '/messages', modelSuffixes: [],
      row: row({ provider: 'anthropic', supportsImageInput: true }),
    });
    assert.equal(native.reason, 'non_text_content', 'native:' + JSON.stringify(payload));
  }
});
