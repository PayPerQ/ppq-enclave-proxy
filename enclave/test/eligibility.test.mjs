import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateDirectEligibility,
  projectAllowedFields,
  refusesUnauthorizedFree,
  IMAGE_DIRECT_PROVIDERS,
  WEB_SEARCH_DIRECT_PROVIDERS,
  ZDR_DIRECT_PROVIDERS,
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
  // Venice is ZDR too (hp parity). The web app sends zdr on every Venice
  // turn, and the OpenRouter bail cannot serve a `venice/*` id — so bailing
  // here was a guaranteed 400, not a longer route (PPQdotAI#2826).
  assert.deepEqual(
    evalE(
      { model: 'venice/venice-uncensored-1-2', messages: msgs, provider: { zdr: true } },
      { row: row({ provider: 'venice' }) },
    ),
    { eligible: true },
  );
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

test('zdr: a per-candidate zdr flag narrows the provider ceiling', () => {
  const venicePayload = { model: 'venice/some-model', messages: msgs, provider: { zdr: true } };
  const venice = (o) => ({ row: row({ provider: 'venice', ...o }) });
  // A provider can serve some models without zero data retention: hp marks
  // those candidates zdr:false, and a ZDR request must not be served by them.
  assert.equal(evalE(venicePayload, venice({ zdr: false })).reason, 'zdr_requested');
  assert.deepEqual(evalE(venicePayload, venice({ zdr: true })), { eligible: true });
  // Absent flag: an hp that predates the field. The provider set decides.
  assert.deepEqual(evalE(venicePayload, venice({})), { eligible: true });
  // Anything present but not literally true is not a ZDR claim.
  for (const v of ['true', 1, null]) {
    assert.equal(evalE(venicePayload, venice({ zdr: v })).reason, 'zdr_requested', String(v));
  }
  // The flag cannot lift a provider above the ceiling.
  assert.equal(evalE(venicePayload, { row: row({ provider: 'anthropic', zdr: true }) }).reason, 'zdr_requested');
  // Foundry joined the ceiling on 2026-10-26 (hp #1139): served direct.
  assert.deepEqual(evalE(venicePayload, { row: row({ provider: 'foundry', zdr: true }) }), { eligible: true });
  // Without a zdr request the flag changes nothing.
  assert.deepEqual(
    evalE({ model: 'venice/some-model', messages: msgs }, venice({ zdr: false })),
    { eligible: true },
  );
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
  // Fireworks on Foundry speaks the same dialect, so the replay follows it.
  const fd = projectAllowedFields(payload, row({ provider: 'foundry' }));
  assert.deepEqual(fd.messages[1], { role: 'assistant', content: 'done', reasoning_content: 'thinking…' });
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

const ANTHROPIC_ROW = () => row({ provider: 'anthropic', supportsTools: true });

test('admits an assistant turn replaying thinking alongside text on the Anthropic seam (opencode agentic; hp parity)', () => {
  // The translator drops it, so it must not bail non_text_content — the biggest
  // direct-route leak before this (2026-09-10 enclave OR-share audit).
  assert.deepEqual(
    evalE(
      {
        model: 'anthropic/claude-sonnet-5',
        messages: [
          { role: 'user', content: 'refactor this' },
          { role: 'assistant', content: [{ type: 'text', text: 'On it.' }, { type: 'reasoning', text: 'The user wants…' }] },
          { role: 'user', content: 'go' },
        ],
      },
      { row: ANTHROPIC_ROW() },
    ),
    { eligible: true },
  );
});

test('reasoning-part tolerance is Anthropic-only: a Fireworks row still bails (no schema-400 gamble)', () => {
  const r = evalE(
    {
      model: 'moonshotai/kimi-k3',
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: [{ type: 'text', text: 'answer' }, { type: 'reasoning', text: 't' }] },
        { role: 'user', content: 'go' },
      ],
    },
    { row: row({ provider: 'fireworks' }) },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('a reasoning-ONLY assistant turn bails (would empty the turn and merge the user turns)', () => {
  const r = evalE(
    {
      model: 'anthropic/claude-sonnet-5',
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: [{ type: 'reasoning', text: 'silent thought' }] },
        { role: 'user', content: 'go' },
      ],
    },
    { row: ANTHROPIC_ROW() },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('an assistant turn of reasoning + an EMPTY text part still bails (empty text also drops → no surviving block)', () => {
  // CodeRabbit on #164: `every(reasoning)` missed this; the translator drops the
  // reasoning part AND the empty text block, emptying the turn.
  const r = evalE(
    {
      model: 'anthropic/claude-sonnet-5',
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: [{ type: 'reasoning', text: 'x' }, { type: 'text', text: '' }] },
        { role: 'user', content: 'go' },
      ],
    },
    { row: ANTHROPIC_ROW() },
  );
  assert.equal(r.reason, 'non_text_content');
});

for (const [label, content] of [['empty string', ''], ['null', null], ['empty array', []]]) {
  test(`a block-less assistant turn (${label} content, no tool_calls) bails on every content form`, () => {
    // CodeRabbit on #164/#908: the empty-turn guard covers string/null/array
    // uniformly — each translates to no blocks and would merge the user turns.
    const r = evalE(
      {
        model: 'anthropic/claude-sonnet-5',
        messages: [
          { role: 'user', content: 'hi' },
          { role: 'assistant', content },
          { role: 'user', content: 'go' },
        ],
      },
      { row: ANTHROPIC_ROW() },
    );
    assert.equal(r.reason, 'non_text_content');
  });
}

test('a block-less assistant turn with ABSENT content (no content property, no tool_calls) bails', () => {
  // message.content is undefined here — same no-surviving-block outcome as null,
  // asserted explicitly so the host/enclave parity is locked (CodeRabbit on #164).
  const r = evalE(
    {
      model: 'anthropic/claude-sonnet-5',
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'assistant' },
        { role: 'user', content: 'go' },
      ],
    },
    { row: ANTHROPIC_ROW() },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('the ordinary assistant tool-call turn (content:null + tool_calls) stays eligible — the guard must not bail it', () => {
  assert.deepEqual(
    evalE(
      {
        model: 'anthropic/claude-sonnet-5',
        messages: [
          { role: 'user', content: 'weather?' },
          { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'f', arguments: '{}' } }] },
          { role: 'tool', tool_call_id: 'c1', content: 'sunny' },
          { role: 'user', content: 'thanks' },
        ],
      },
      { row: ANTHROPIC_ROW() },
    ),
    { eligible: true },
  );
});

test('a reasoning-only assistant turn WITH tool_calls is admitted (tool_calls survive translation)', () => {
  assert.deepEqual(
    evalE(
      {
        model: 'anthropic/claude-sonnet-5',
        messages: [
          { role: 'user', content: 'hi' },
          {
            role: 'assistant',
            content: [{ type: 'reasoning', text: 't' }],
            tool_calls: [{ id: 'c1', type: 'function', function: { name: 'f', arguments: '{}' } }],
          },
          { role: 'tool', tool_call_id: 'c1', content: 'result' },
          { role: 'user', content: 'go' },
        ],
      },
      { row: ANTHROPIC_ROW() },
    ),
    { eligible: true },
  );
});

test('reasoning content parts are assistant-only: a USER reasoning part still bails', () => {
  const r = evalE(
    {
      model: 'anthropic/claude-sonnet-5',
      messages: [{ role: 'user', content: [{ type: 'reasoning', text: 'users do not think out loud on the wire' }] }],
    },
    { row: ANTHROPIC_ROW() },
  );
  assert.equal(r.reason, 'non_text_content');
});

test('json_schema response_format: Fireworks-stack rows only; text/json_object pass everywhere (hp #1139 phase 3)', () => {
  const schema = { name: 'city', strict: true, schema: { type: 'object', properties: { city: { type: 'string' } } } };
  const payload = { model: 'moonshotai/kimi-k3', messages: msgs, response_format: { type: 'json_schema', json_schema: schema } };
  // Fireworks and Foundry returned schema-conforming JSON for this shape (probed 2026-10-26).
  assert.deepEqual(evalE(payload), { eligible: true });
  assert.deepEqual(evalE(payload, { row: row({ provider: 'foundry', upstreamModelId: 'FW-Kimi-K3' }) }), { eligible: true });
  // Forwarded verbatim: the provider sees the schema the caller wrote.
  assert.deepEqual(projectAllowedFields(payload, row()).response_format, payload.response_format);
  // Any other row keeps bailing — OpenRouter normalizes strict conformance there.
  assert.equal(evalE(payload, { row: row({ provider: 'anthropic' }) }).reason, 'response_format_unsupported');
  assert.equal(evalE(payload, { row: undefined }).reason, 'response_format_unsupported');
  // A `json_schema` member that is not an object bails even on Fireworks.
  assert.equal(evalE({ ...payload, response_format: { type: 'json_schema' } }).reason, 'response_format_unsupported');
  assert.equal(evalE({ ...payload, response_format: { type: 'json_schema', json_schema: 'x' } }).reason, 'response_format_unsupported');
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

test('admits data-URI images on fireworks and foundry rows that advertise image support (hp #1139)', () => {
  for (const provider of ['fireworks', 'foundry']) {
    assert.deepEqual(
      evalE({ model: 'moonshotai/kimi-k3', messages: [imgMsg(IMG)] }, { row: row({ provider, supportsImageInput: true }) }),
      { eligible: true },
      provider,
    );
    // Row-gated: a Fireworks-stack row that does not advertise vision still bails.
    assert.equal(
      evalE({ model: 'z-ai/glm-5.3', messages: [imgMsg(IMG)] }, { row: row({ provider, supportsImageInput: false }) }).reason,
      'non_text_content',
      provider,
    );
  }
});

test('fireworks/foundry rows take png, jpeg and webp only; heic/heif bail (hp #1139 probe)', () => {
  const ok = (t) => `data:image/${t};base64,${IMG.slice(IMG.indexOf(';base64,') + ';base64,'.length)}`;
  for (const provider of ['fireworks', 'foundry']) {
    for (const t of ['png', 'jpeg', 'webp']) {
      assert.deepEqual(
        evalE({ model: 'moonshotai/kimi-k3', messages: [imgMsg(ok(t))] }, { row: row({ provider, supportsImageInput: true }) }),
        { eligible: true },
        `${provider}/${t}`,
      );
    }
    for (const t of ['heic', 'heif']) {
      assert.equal(
        evalE({ model: 'moonshotai/kimi-k3', messages: [imgMsg(ok(t))] }, { row: row({ provider, supportsImageInput: true }) }).reason,
        'non_text_content',
        `${provider}/${t}`,
      );
    }
  }
  // The shared set is unchanged for providers with their own boundary.
  assert.deepEqual(
    evalE({ model: 'google/gemini-2.5-flash', messages: [imgMsg(ok('heic'))] }, { row: vertexRow() }),
    { eligible: true },
  );
});

test('IMAGE_DIRECT_PROVIDERS is default-closed: a vision-claiming row of an unlisted provider still bails', () => {
  const r = evalE(
    { model: 'moonshotai/kimi-k3', messages: [imgMsg(IMG)] },
    { row: row({ provider: 'tinfoil', supportsImageInput: true }) },
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

test('message-level cache_control: ephemeral admitted, kept for anthropic, stripped elsewhere', () => {
  const marked = (cc) => [
    { role: 'user', content: 'context', cache_control: cc },
    { role: 'user', content: 'question' },
  ];
  for (const cc of [{ type: 'ephemeral' }, { type: 'ephemeral', ttl: '5m' }]) {
    assert.deepEqual(evalE({ model: 'moonshotai/kimi-k3', messages: marked(cc) }), { eligible: true });
  }
  for (const cc of [{ type: 'persistent' }, { type: 'ephemeral', ttl: '2h' }, 'ephemeral', null]) {
    const r = evalE({ model: 'moonshotai/kimi-k3', messages: marked(cc) });
    assert.equal(r.reason, 'unsupported_message_field', JSON.stringify(cc));
    assert.equal(r.offendingField, 'cache_control');
  }
  const payload = { model: 'm', stream: true, messages: marked({ type: 'ephemeral' }) };
  const kept = projectAllowedFields(payload, row({ provider: 'anthropic' }));
  assert.deepEqual(kept.messages[0].cache_control, { type: 'ephemeral' });
  const stripped = projectAllowedFields(payload, row());
  assert.equal('cache_control' in stripped.messages[0], false);
  // The client payload is untouched.
  assert.deepEqual(payload.messages[0].cache_control, { type: 'ephemeral' });
});

test('safety_settings: admitted on any row, forwarded to vertex, stripped elsewhere, malformed bails', () => {
  const SS = [{ category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' }];
  const payload = { model: 'google/gemini-2.5-flash', stream: true, messages: msgs, safety_settings: SS };
  // Admitted on any provider (gate is provider-neutral).
  for (const provider of ['vertex', 'fireworks', 'anthropic', 'bedrock']) {
    assert.deepEqual(evalE(payload, { row: row({ provider }) }), { eligible: true }, provider);
  }
  // Forwarded for vertex, stripped elsewhere.
  const kept = projectAllowedFields(payload, row({ provider: 'vertex' }));
  assert.deepEqual(kept.safety_settings, SS);
  const stripped = projectAllowedFields(payload, row({ provider: 'fireworks' }));
  assert.equal('safety_settings' in stripped, false);
  // Malformed bails with the member named.
  for (const [ss, member] of [
    [[], 'safety_settings'],
    [[{ category: 'HARM_CATEGORY_UNKNOWN', threshold: 'BLOCK_NONE' }], 'safety_settings.category'],
    [[{ category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'NOPE' }], 'safety_settings.threshold'],
  ]) {
    const r = evalE({ ...payload, safety_settings: ss }, { row: row({ provider: 'vertex' }) });
    assert.equal(r.reason, 'unmappable_field');
    assert.equal(r.offendingField, member);
  }
  // Client payload untouched.
  assert.deepEqual(payload.safety_settings, SS);
});

test('verbosity: admitted and forwarded for bedrock only; other rows keep bailing unsupported_field', () => {
  const payload = { model: 'openai/gpt-6-luna', stream: true, messages: msgs, verbosity: 'low' };
  assert.deepEqual(evalE(payload, { row: row({ provider: 'bedrock' }) }), { eligible: true });
  assert.equal(projectAllowedFields(payload, row({ provider: 'bedrock' })).verbosity, 'low');
  // Every other provider: the pre-existing bail, same reason string.
  for (const provider of ['fireworks', 'vertex', 'anthropic']) {
    const r = evalE(payload, { row: row({ provider }) });
    assert.equal(r.reason, 'unsupported_field', provider);
    assert.equal(r.offendingField, 'verbosity', provider);
    assert.equal('verbosity' in projectAllowedFields(payload, row({ provider })), false, provider);
  }
  // Row-less: unchanged.
  assert.equal(evalE(payload).reason, 'unsupported_field');
  // An undocumented value on a bedrock row bails with the field named.
  const bad = evalE({ ...payload, verbosity: 'loud' }, { row: row({ provider: 'bedrock' }) });
  assert.equal(bad.reason, 'unmappable_field');
  assert.equal(bad.offendingField, 'verbosity');
  // The /messages dialect never takes it.
  const msgsDialect = evalE({ model: 'm', max_tokens: 10, messages: msgs, verbosity: 'low' }, { path: '/messages', row: row({ provider: 'bedrock' }) });
  assert.equal(msgsDialect.reason, 'unsupported_field');
});

// ── Bedrock image admission (2026-09-10) + unhonored client fields (#861) ────

const bedrockRow = (o = {}) =>
  row({ provider: 'bedrock', upstreamModelId: 'openai.gpt-6-astra', supportsImageInput: true, ...o });

test('admits data-URI images on a bedrock row that advertises image support', () => {
  assert.deepEqual(
    evalE({ model: 'openai/gpt-6-astra', messages: [imgMsg(IMG)] }, { row: bedrockRow() }),
    { eligible: true },
  );
});

test('bails when the bedrock row does not advertise image support, and on assistant-turn images', () => {
  assert.equal(
    evalE({ model: 'openai/gpt-6-astra', messages: [imgMsg(IMG)] }, { row: bedrockRow({ supportsImageInput: false }) }).reason,
    'non_text_content',
  );
  assert.equal(
    evalE({ model: 'openai/gpt-6-astra', messages: [msgs[0], imgMsg(IMG, 'assistant')] }, { row: bedrockRow() }).reason,
    'non_text_content',
  );
});

test('unhonored client fields (store, prompt_cache_key, …) no longer cost the direct route; unknown fields still bail', () => {
  const payload = { model: 'moonshotai/kimi-k3', messages: msgs, store: true, prompt_cache_key: 'k', promptCacheKey: 'k', compact_model: 'm', inheritProjectContext: false };
  assert.deepEqual(evalE(payload), { eligible: true });
  // Never forwarded either — not in ALLOWED_FIELDS, so projection drops them.
  const body = projectAllowedFields(payload, row());
  for (const k of ['store', 'prompt_cache_key', 'promptCacheKey', 'compact_model', 'inheritProjectContext']) {
    assert.equal(k in body, false, k);
  }
  const unknown = evalE({ model: 'moonshotai/kimi-k3', messages: msgs, some_new_knob: 1 });
  assert.equal(unknown.reason, 'unsupported_field');
  assert.equal(unknown.offendingField, 'some_new_knob');
});

test('prompt_cache_retention and a boolean include_reasoning no longer cost the direct route (hp #997)', () => {
  for (const extra of [{ prompt_cache_retention: '24h' }, { include_reasoning: true }, { include_reasoning: false }]) {
    const payload = { model: 'moonshotai/kimi-k3', messages: msgs, ...extra };
    assert.deepEqual(evalE(payload), { eligible: true }, JSON.stringify(extra));
    const body = projectAllowedFields(payload, row());
    for (const k of Object.keys(extra)) assert.equal(k in body, false, k);
  }
  const bad = evalE({ model: 'moonshotai/kimi-k3', messages: msgs, include_reasoning: 'yes' });
  assert.equal(bad.reason, 'unsupported_field');
  assert.equal(bad.offendingField, 'include_reasoning');
});

test("OpenRouter's `usage` accounting flag no longer costs the direct route (hp #1139)", () => {
  for (const usage of [{ include: true }, { include: false }, true]) {
    const payload = { model: 'moonshotai/kimi-k3', messages: msgs, usage };
    assert.deepEqual(evalE(payload), { eligible: true }, JSON.stringify(usage));
    const body = projectAllowedFields(payload, row());
    assert.equal('usage' in body, false);
    // The direct path still pins usage on the stream it asked for.
    const streamed = projectAllowedFields({ ...payload, stream: true }, row());
    assert.equal(streamed.stream_options?.include_usage, true);
  }
});

test('`cot_id` still bails on the /messages dialect (chat-only admission, hp #1139)', () => {
  const r = evalE(
    { model: 'moonshotai/kimi-k3', max_tokens: 10, messages: [{ role: 'user', content: 'hi', cot_id: 'cot-abc' }] },
    { path: '/messages' },
  );
  assert.equal(r.reason, 'unsupported_message_field');
  assert.equal(r.offendingField, 'cot_id');
});

test('`cot_id` on a message is admitted and dropped at projection for every provider (hp #1139)', () => {
  const payload = {
    model: 'moonshotai/kimi-k3',
    messages: [
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: 'hello', cot_id: 'cot-abc' },
      { role: 'user', content: 'again', cot_id: 'cot-def' },
    ],
  };
  for (const provider of ['fireworks', 'foundry', 'anthropic', 'vertex']) {
    assert.deepEqual(evalE(payload, { row: row({ provider }) }), { eligible: true }, provider);
    const body = projectAllowedFields(payload, row({ provider }));
    for (const m of body.messages) assert.equal('cot_id' in m, false, provider);
  }
  // Never-mutate contract: the caller's messages keep their cot_id.
  assert.equal(payload.messages[1].cot_id, 'cot-abc');
  // The content and the other members survive untouched.
  const fw = projectAllowedFields(payload, row());
  assert.deepEqual(fw.messages[1], { role: 'assistant', content: 'hello' });
});

test('ZDR_DIRECT_PROVIDERS matches horse-power (services/directProviders/types.ts)', () => {
  // Pinned as a literal because this set drifting from hp is silent: the
  // request still gets an answer — a 400 from the wrong upstream.
  assert.deepEqual([...ZDR_DIRECT_PROVIDERS].sort(), ['fireworks', 'foundry', 'venice']);
});

// ── Venice: native web search and image input (hp parity) ───────────────────
// Venice's models exist on no other route, so every bail here is a failed
// request, not a fallback. hp serves both natively; so does this gate.

const veniceRow = (o = {}) =>
  row({ provider: 'venice', orSlug: 'venice/venice-uncensored-1-2', supportsTools: false, ...o });
const venicePayload = (extra = {}) => ({
  model: 'venice/venice-uncensored-1-2',
  messages: msgs,
  provider: { zdr: true },
  ...extra,
});

test('venice: the web plugin stays direct (the web app sends it on every search turn)', () => {
  const web = { plugins: [{ id: 'web', max_results: 5 }] };
  assert.deepEqual(evalE(venicePayload(web), { row: veniceRow() }), { eligible: true });
  // Every other provider still forces OpenRouter, which is what runs the search.
  assert.equal(evalE({ model: 'moonshotai/kimi-k3', messages: msgs, ...web }).reason, 'web_search_requires_openrouter');
});

test('venice: the web-search server tool stays direct and is not counted as a function tool', () => {
  for (const type of ['web_search', 'openrouter:web_search']) {
    // supportsTools is false on this row: the search tool must not trip it.
    assert.deepEqual(evalE(venicePayload({ tools: [{ type }] }), { row: veniceRow() }), { eligible: true });
  }
  // A real function tool on a row without tool support still bails.
  const fn = { type: 'function', function: { name: 'f', parameters: {} } };
  assert.equal(
    evalE(venicePayload({ tools: [{ type: 'web_search' }, fn] }), { row: veniceRow() }).reason,
    'tools_unsupported_by_model',
  );
  assert.deepEqual(
    evalE(venicePayload({ tools: [{ type: 'web_search' }, fn] }), { row: veniceRow({ supportsTools: true }) }),
    { eligible: true },
  );
});

test("venice: Anthropic's dated web-search tool is not the same thing and still bails", () => {
  const dated = { tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }] };
  assert.equal(
    evalE(venicePayload(dated), { row: veniceRow({ supportsTools: true }) }).reason,
    'web_search_requires_openrouter',
  );
  assert.equal(
    evalE(venicePayload({ ...dated, plugins: [{ id: 'web' }] }), { row: veniceRow({ supportsTools: true }) }).reason,
    'web_search_requires_openrouter',
  );
});

test('venice: data-URI images are admitted on a row that advertises image support, and only there', () => {
  const img = `data:image/png;base64,${'A'.repeat(64)}`;
  const withImage = venicePayload({
    messages: [{ role: 'user', content: [{ type: 'text', text: 'what is this' }, { type: 'image_url', image_url: { url: img } }] }],
  });
  assert.deepEqual(evalE(withImage, { row: veniceRow({ supportsImageInput: true }) }), { eligible: true });
  assert.equal(evalE(withImage, { row: veniceRow({ supportsImageInput: false }) }).reason, 'non_text_content');
});

test('venice: a malformed tools value does not throw (CodeRabbit, #263)', () => {
  // `tools` is allowlisted without a shape check, so these reach the
  // function-tool count. They must come back as a decision, never a TypeError
  // that the route handler turns into a 500.
  for (const tools of ['web_search', { type: 'web_search' }, 7, true, null]) {
    for (const r of [veniceRow(), veniceRow({ supportsTools: true })]) {
      assert.doesNotThrow(() => evalE(venicePayload({ tools }), { row: r }), `tools=${JSON.stringify(tools)}`);
      assert.deepEqual(evalE(venicePayload({ tools }), { row: r }), { eligible: true });
    }
  }
});

test('provider sets match horse-power (services/directProviders/types.ts)', () => {
  assert.deepEqual([...WEB_SEARCH_DIRECT_PROVIDERS].sort(), ['venice']);
  assert.deepEqual([...IMAGE_DIRECT_PROVIDERS].sort(), ['anthropic', 'bedrock', 'fireworks', 'foundry', 'openai', 'venice', 'vertex']);
});

// ── provider object absorption (hp #969 parity + #1139 phase 3) ─────────────

test('provider.ignore: absorbed when it does not name the row provider, bails when it does (hp #969 parity)', () => {
  const p = (provider) => ({ model: 'moonshotai/kimi-k3', messages: msgs, provider });
  assert.deepEqual(evalE(p({ ignore: ['deepinfra', 'Novita'] })), { eligible: true });
  for (const entry of ['fireworks', 'Fireworks', 'fireworks/fast', '  FIREWORKS  ']) {
    const r = evalE(p({ ignore: ['deepinfra', entry] }));
    assert.equal(r.reason, 'unsupported_field', entry);
    assert.equal(r.offendingField, 'provider', entry);
  }
  // OpenRouter's spellings of the other direct providers.
  for (const [provider, entry] of [
    ['bedrock', 'Amazon Bedrock'],
    ['bedrock', 'amazon-bedrock'],
    ['vertex', 'Google Vertex'],
    ['vertex', 'google-vertex'],
    ['anthropic', 'Anthropic'],
    ['foundry', 'azure'],
    ['foundry', 'Fireworks'],
    ['openai', 'OpenAI'],
    ['openai', 'openai'],
  ]) {
    assert.equal(evalE(p({ ignore: [entry] }), { row: row({ provider }) }).eligible, false, `${provider}/${entry}`);
  }
  // Never forwarded.
  assert.equal('provider' in projectAllowedFields(p({ ignore: ['deepinfra'] }), row()), false);
  // Alongside zdr on a ZDR row.
  assert.deepEqual(evalE(p({ zdr: true, ignore: ['deepinfra'] })), { eligible: true });
  // Malformed shapes and unhonorable company still bail.
  for (const [label, provider] of [
    ['a non-array ignore', { ignore: 'deepinfra' }],
    ['a non-string entry', { ignore: ['deepinfra', 42] }],
    ['an oversized list', { ignore: Array.from({ length: 65 }, (_, i) => `p${i}`) }],
    ['ignore plus a routing directive', { ignore: ['deepinfra'], order: ['alibaba'] }],
    ['ignore plus allow_fallbacks', { ignore: ['deepinfra'], allow_fallbacks: false }],
    ['zdr false', { zdr: false, ignore: ['deepinfra'] }],
    ['an empty object', {}],
  ]) {
    const r = evalE(p(provider));
    assert.equal(r.eligible, false, label);
    assert.equal(r.offendingField, 'provider', label);
  }
  // No row: an ignore list cannot be judged, so it bails (the catalog check
  // would bail anyway; the provider bail comes first in the sweep).
  assert.equal(evalE(p({ ignore: ['deepinfra'] }), { row: undefined }).eligible, false);
});

test('provider.order / provider.only naming the row provider are absorbed (hp #1139 phase 3)', () => {
  const p = (provider) => ({ model: 'moonshotai/kimi-k3', messages: msgs, provider });
  // order: the FIRST preference is this provider.
  assert.deepEqual(evalE(p({ order: ['Fireworks', 'together'] })), { eligible: true });
  assert.deepEqual(evalE(p({ order: ['fireworks'], allow_fallbacks: false })), { eligible: true });
  assert.deepEqual(evalE(p({ order: ['fireworks/fast'], allow_fallbacks: true })), { eligible: true });
  // only: every permitted provider is this one.
  assert.deepEqual(evalE(p({ only: ['fireworks'] })), { eligible: true });
  assert.deepEqual(evalE(p({ only: ['fireworks'], zdr: true })), { eligible: true });
  // A Foundry row is Fireworks' stack: a Fireworks pin is served by it.
  const foundry = row({ provider: 'foundry', upstreamModelId: 'FW-Kimi-K3' });
  assert.deepEqual(evalE(p({ order: ['fireworks'] }), { row: foundry }), { eligible: true });
  assert.deepEqual(evalE(p({ only: ['Fireworks'] }), { row: foundry }), { eligible: true });
  // Never forwarded: the pin stays on the caller's body for the OpenRouter fallback only.
  const pinned = p({ order: ['fireworks'], allow_fallbacks: false });
  assert.equal('provider' in projectAllowedFields(pinned, row()), false);
  assert.deepEqual(pinned.provider, { order: ['fireworks'], allow_fallbacks: false });
  // Still bail: another provider first / among the only set, empty lists,
  // allow_fallbacks on its own, sort or any other directive alongside.
  for (const [label, provider] of [
    ['order naming another provider first', { order: ['together', 'fireworks'] }],
    ['only including another provider', { only: ['fireworks', 'together'] }],
    ['empty order', { order: [] }],
    ['empty only', { only: [] }],
    ['non-string order entry', { order: [1] }],
    ['allow_fallbacks alone', { allow_fallbacks: false }],
    ['non-boolean allow_fallbacks', { order: ['fireworks'], allow_fallbacks: 'no' }],
    ['order plus sort', { order: ['fireworks'], sort: 'price' }],
    ['order plus max_price', { order: ['fireworks'], max_price: { prompt: 1 } }],
  ]) {
    const r = evalE(p(provider));
    assert.equal(r.eligible, false, label);
    assert.equal(r.offendingField, 'provider', label);
  }
  // Pins are judged on the NARROW table: azure/microsoft are not Foundry and
  // google is not Vertex — while the same spellings in an ignore list still
  // keep those rows off (broad table).
  for (const entry of ['azure', 'Microsoft', 'Azure/fast']) {
    assert.equal(evalE(p({ only: [entry] }), { row: foundry }).eligible, false, `only ${entry}`);
    assert.equal(evalE(p({ order: [entry] }), { row: foundry }).eligible, false, `order ${entry}`);
    assert.equal(evalE(p({ ignore: [entry] }), { row: foundry }).eligible, false, `ignore ${entry}`);
  }
  const vertex = row({ provider: 'vertex', upstreamModelId: 'google/gemini-2.5-flash' });
  assert.equal(evalE(p({ order: ['google'] }), { row: vertex }).eligible, false);
  assert.deepEqual(evalE(p({ order: ['google-vertex'] }), { row: vertex }), { eligible: true });
  assert.equal(evalE(p({ ignore: ['google'] }), { row: vertex }).eligible, false);
  // A pin on a row of another provider bails (OpenRouter enforces it).
  assert.equal(evalE(p({ order: ['fireworks'] }), { row: row({ provider: 'anthropic' }) }).eligible, false);
  assert.equal(evalE(p({ only: ['anthropic'] })).eligible, false);
});

test('Ollama-client fields (options, keep_alive, think, num_gpu) and source_ip no longer cost the direct route (hp #1139 phase 3)', () => {
  const payload = { model: 'moonshotai/kimi-k3', messages: msgs, options: { temperature: 0.1, num_ctx: 8192 }, keep_alive: '5m', think: false, num_gpu: 1, source_ip: '203.0.113.9' };
  assert.deepEqual(evalE(payload), { eligible: true });
  const body = projectAllowedFields(payload, row());
  for (const k of ['options', 'keep_alive', 'think', 'num_gpu', 'source_ip']) assert.equal(k in body, false, k);
  // The messages dialect takes the same posture (the set is dialect-agnostic).
  assert.deepEqual(
    evaluateDirectEligibility({ payload: { model: 'moonshotai/kimi-k3', max_tokens: 10, messages: msgs, keep_alive: '5m' }, path: '/messages', modelSuffixes: [], row: row() }),
    { eligible: true },
  );
});

test("openai first-party: hp's own OpenAI-family preference is absorbed by an openai row (horse-power #1157 / #1111)", () => {
  const openai = row({ provider: 'openai', upstreamModelId: 'gpt-5.5', supportsImageInput: true });
  const p = (provider) => ({ model: 'openai/gpt-5.5', messages: msgs, provider });
  // What hp sends for every openai/* request since #1111.
  assert.deepEqual(evalE(p({ order: ['openai'], allow_fallbacks: true, ignore: ['amazon-bedrock'] }), { row: openai }), { eligible: true });
  assert.deepEqual(evalE(p({ only: ['openai'] }), { row: openai }), { eligible: true });
  // Never forwarded.
  assert.equal('provider' in projectAllowedFields(p({ order: ['openai'] }), openai), false);
  // A caller excluding OpenAI, or pinning OpenRouter's Azure endpoint, keeps the row off.
  assert.equal(evalE(p({ ignore: ['OpenAI'] }), { row: openai }).eligible, false);
  assert.equal(evalE(p({ order: ['azure'] }), { row: openai }).eligible, false);
  // Not ZDR: a Private-mode turn bails to OpenRouter.
  assert.equal(evalE(p({ zdr: true }), { row: openai }).reason, 'zdr_requested');
  // verbosity is honored on the openai row (same translator as bedrock).
  assert.deepEqual(evalE({ model: 'openai/gpt-5.5', messages: msgs, verbosity: 'low' }, { row: openai }), { eligible: true });
  assert.equal(projectAllowedFields({ model: 'openai/gpt-5.5', messages: msgs, verbosity: 'low' }, openai).verbosity, 'low');
});
