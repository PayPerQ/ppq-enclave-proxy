import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ANTHROPIC_MAPPABLE_FIELDS,
  toMessagesRequest,
  buildAnthropicRequest,
  MessagesToChatSse,
} from '../src/anthropic.mjs';
import { CostExtractor } from '../src/cost.mjs';
import { directResponseRewriter } from '../src/rebrand.mjs';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CANDIDATE = {
  provider: 'anthropic',
  api_style: 'anthropic',
  host: 'api.anthropic.com',
  path: '/v1/messages',
  key_ref: 'anthropic',
  upstream_model: 'claude-sonnet-4-6',
  or_slug: 'anthropic/claude-sonnet-4.6',
  supports_tools: true,
  supports_image_input: false,
  context_length: 200000,
};

const PORTS = { 'api.anthropic.com': 9448 };
const KEYS = { anthropic: 'sk-ant-test-key' };

function basePayload(overrides = {}) {
  return {
    model: 'anthropic/claude-sonnet-4.6',
    stream: true,
    messages: [{ role: 'user', content: 'hello' }],
    ...overrides,
  };
}

// projectAllowedFields output shape, hand-rolled for direct translator tests.
function projected(overrides = {}) {
  return {
    model: 'claude-sonnet-4-6',
    stream: true,
    stream_options: { include_usage: true },
    messages: [{ role: 'user', content: 'hello' }],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// toMessagesRequest
// ---------------------------------------------------------------------------

test('maps a full conversation: system hoist, tool round-trip, alternation merging, cache marks', () => {
  const out = toMessagesRequest(
    projected({
      messages: [
        { role: 'system', content: 'be terse' },
        { role: 'user', content: [{ type: 'text', text: 'weather in Lisbon?' }] },
        {
          role: 'assistant',
          content: null,
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: { name: 'get_weather', arguments: '{"city":"Lisbon"}' },
            },
          ],
        },
        { role: 'tool', tool_call_id: 'call_1', content: '{"temp_c":21}' },
        { role: 'user', content: 'and tomorrow?' },
      ],
      max_tokens: 512,
      temperature: 0.7,
      top_p: 0.9,
      top_k: 40,
      stop: 'END',
      tools: [
        {
          type: 'function',
          function: {
            name: 'get_weather',
            description: 'Weather lookup',
            parameters: { type: 'object', properties: { city: { type: 'string' } } },
          },
        },
      ],
      tool_choice: 'auto',
    }),
  );

  assert.equal(out.skip, undefined);
  const body = out.body;
  assert.equal(body.model, 'claude-sonnet-4-6');
  assert.equal(body.max_tokens, 512);
  assert.equal(body.stream, true);
  assert.deepEqual(body.system, [{ type: 'text', text: 'be terse' }]);
  assert.equal(body.temperature, 0.7);
  assert.equal(body.top_p, 0.9);
  assert.equal(body.top_k, 40);
  assert.deepEqual(body.stop_sequences, ['END']);
  assert.deepEqual(body.tools, [
    {
      name: 'get_weather',
      input_schema: { type: 'object', properties: { city: { type: 'string' } } },
      description: 'Weather lookup',
    },
  ]);
  assert.deepEqual(body.tool_choice, { type: 'auto' });

  // Turn structure: user → assistant(tool_use) → user(tool_result + text,
  // MERGED — the Messages API requires strict alternation). Cache marks land
  // on messages[0] and the last user turns' last non-empty text part.
  assert.equal(body.messages.length, 3);
  assert.equal(body.messages[0].role, 'user');
  assert.deepEqual(body.messages[1], {
    role: 'assistant',
    content: [
      { type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Lisbon' } },
    ],
  });
  assert.equal(body.messages[2].role, 'user');
  assert.equal(body.messages[2].content[0].type, 'tool_result');
  assert.equal(body.messages[2].content[0].tool_use_id, 'call_1');
  const lastText = body.messages[2].content.at(-1);
  assert.equal(lastText.text, 'and tomorrow?');
  assert.deepEqual(lastText.cache_control, { type: 'ephemeral' });
  assert.deepEqual(body.messages[0].content.at(-1).cache_control, { type: 'ephemeral' });

  // OpenAI-isms never reach the wire.
  assert.equal(body.stream_options, undefined);
});

test('max_tokens is REQUIRED by the API — defaulted when the chat client omits it', () => {
  assert.equal(toMessagesRequest(projected()).body.max_tokens, 8192);
  assert.equal(
    toMessagesRequest(projected({ max_tokens: 100, max_completion_tokens: 200 })).body.max_tokens,
    200,
  );
});

test('tool_choice mappings: required → any, named → tool, none → tools omitted', () => {
  const tools = [{ type: 'function', function: { name: 'f', parameters: {} } }];
  assert.deepEqual(
    toMessagesRequest(projected({ tools, tool_choice: 'required' })).body.tool_choice,
    { type: 'any' },
  );
  assert.deepEqual(
    toMessagesRequest(
      projected({ tools, tool_choice: { type: 'function', function: { name: 'f' } } }),
    ).body.tool_choice,
    { type: 'tool', name: 'f' },
  );
  const none = toMessagesRequest(projected({ tools, tool_choice: 'none' })).body;
  assert.equal(none.tools, undefined);
  assert.equal(none.tool_choice, undefined);
});

test('unmappable projected fields skip the candidate with the field named', () => {
  for (const [field, value] of [
    ['response_format', { type: 'json_object' }],
    ['seed', 42],
    ['frequency_penalty', 0.5],
    ['logit_bias', { 50256: -100 }],
    ['n', 2],
    ['min_p', 0.1],
    ['parallel_tool_calls', false],
    // reasoning_effort used to live here; it now maps to `thinking` (#2646).
  ]) {
    const out = toMessagesRequest(projected({ [field]: value }));
    assert.equal(out.skip, 'anthropic_unmappable_field', field);
    assert.equal(out.offendingField, field);
  }
});

test('structural refusals: non-streaming, mid-conversation system, assistant-first, bad tool args', () => {
  assert.equal(toMessagesRequest(projected({ stream: undefined })).skip, 'anthropic_stream_only');

  const midSystem = toMessagesRequest(
    projected({
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'system', content: 'now be rude' },
      ],
    }),
  );
  assert.equal(midSystem.skip, 'anthropic_unmappable_field');
  assert.equal(midSystem.offendingField, 'messages.system');

  // The Messages API requires the first turn to be a user turn.
  assert.equal(
    toMessagesRequest(projected({ messages: [{ role: 'assistant', content: 'hi there' }] })).skip,
    'anthropic_unmappable_field',
  );

  const badArgs = toMessagesRequest(
    projected({
      messages: [
        { role: 'user', content: 'q' },
        {
          role: 'assistant',
          tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: '{oops' } }],
        },
      ],
    }),
  );
  assert.equal(badArgs.skip, 'anthropic_unmappable_field');
  assert.equal(badArgs.offendingField, 'messages.tool_calls');
});

test('every mappable field is either consumed or expressed', () => {
  const out = toMessagesRequest(
    projected({
      temperature: 1,
      top_p: 0.5,
      top_k: 20,
      max_tokens: 10,
      max_completion_tokens: 20,
      stop: ['a'],
      tools: [{ type: 'function', function: { name: 'f', parameters: {} } }],
      tool_choice: 'auto',
      user: 'ppq-hash',
    }),
  );
  assert.equal(out.skip, undefined);
  assert.equal(out.body.user, undefined); // consumed, never forwarded
  assert.equal(ANTHROPIC_MAPPABLE_FIELDS.has('messages'), true);
});

// ---------------------------------------------------------------------------
// buildAnthropicRequest
// ---------------------------------------------------------------------------

test('builds an x-api-key /v1/messages request through the vsock tunnel mouth', () => {
  const built = buildAnthropicRequest({
    candidate: CANDIDATE,
    basePayload: basePayload(),
    ports: PORTS,
    keys: KEYS,
  });

  assert.equal(built.skip, undefined);
  assert.equal(built.provider, 'anthropic');
  assert.equal(built.orSlug, 'anthropic/claude-sonnet-4.6');
  assert.equal(built.upstreamModel, 'claude-sonnet-4-6');
  assert.equal(built.apiStyle, 'anthropic');

  const { opts, bodyStr } = built;
  assert.equal(opts.host, '127.0.0.1');
  assert.equal(opts.port, 9448);
  assert.equal(opts.servername, 'api.anthropic.com'); // E2E TLS pin to the real host
  assert.equal(opts.path, '/v1/messages');
  assert.equal(opts.headers.host, 'api.anthropic.com');
  assert.equal(opts.headers['x-api-key'], 'sk-ant-test-key');
  assert.equal(opts.headers['anthropic-version'], '2023-06-01');
  assert.equal(opts.headers.authorization, undefined); // never Bearer
  assert.equal(opts.headers.accept, 'text/event-stream');
  assert.equal(opts.headers['content-length'], Buffer.byteLength(bodyStr));
  // No beta header: 1M context is native where available; the old
  // context-1m-2025-08-07 beta is retired (Anthropic context-windows doc).
  assert.equal(opts.headers['anthropic-beta'], undefined);

  const body = JSON.parse(bodyStr);
  assert.equal(body.model, 'claude-sonnet-4-6'); // wire identity from the row
  assert.equal(body.max_tokens, 8192);
});

test('service_tier: API-valid values forward, provider-foreign values skip the candidate', () => {
  // The value is row-originated (projectAllowedFields injects row.serviceTier),
  // never client input. Anthropic accepts auto/standard_only; a Fireworks-style
  // 'priority' must SKIP — its rates assume a tier this API can't honor.
  const ok = toMessagesRequest(projected({ service_tier: 'standard_only' }));
  assert.equal(ok.skip, undefined);
  assert.equal(ok.body.service_tier, 'standard_only');

  const foreign = toMessagesRequest(projected({ service_tier: 'priority' }));
  assert.equal(foreign.skip, 'anthropic_unmappable_field');
  assert.equal(foreign.offendingField, 'service_tier');
});

test('skips cleanly: no tunnel, no key', () => {
  const args = { candidate: CANDIDATE, basePayload: basePayload(), ports: PORTS, keys: KEYS };
  assert.equal(buildAnthropicRequest({ ...args, ports: {} }).skip, 'no_tunnel_or_key');
  assert.equal(buildAnthropicRequest({ ...args, keys: {} }).skip, 'no_tunnel_or_key');
});

test('the SHARED eligibility gate still runs first (web search bails to OpenRouter)', () => {
  const built = buildAnthropicRequest({
    candidate: CANDIDATE,
    basePayload: basePayload({ plugins: [{ id: 'web' }] }),
    ports: PORTS,
    keys: KEYS,
  });
  assert.equal(built.skip, 'web_search_requires_openrouter');
});

// ---------------------------------------------------------------------------
// MessagesToChatSse — through the REAL CostExtractor + rewriter
// ---------------------------------------------------------------------------

const sse = (obj) => `event: ${obj.type}\ndata: ${JSON.stringify(obj)}\n\n`;

/** A faithful Messages streaming sequence with a warm-cache additive usage. */
function textStream() {
  return [
    sse({
      type: 'message_start',
      message: {
        id: 'msg_01',
        type: 'message',
        role: 'assistant',
        model: 'claude-sonnet-4-6-20250514', // dated wire echo
        usage: { input_tokens: 3, cache_read_input_tokens: 7907, cache_creation_input_tokens: 12, output_tokens: 1 },
      },
    }),
    sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
    sse({ type: 'ping' }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'It is ' } }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'sunny.' } }),
    sse({ type: 'content_block_stop', index: 0 }),
    sse({ type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 5 } }),
    sse({ type: 'message_stop' }),
  ].join('');
}

test('translates a Messages stream into chat SSE the existing pipeline understands', () => {
  const translator = new MessagesToChatSse({ upstreamModel: 'claude-sonnet-4-6' });
  const extractor = new CostExtractor({ isFreeModel: false });
  const rewriter = directResponseRewriter('claude-sonnet-4-6', 'anthropic/claude-sonnet-4.6');

  // Ugly fragmentation: 7-byte strides.
  const wire = Buffer.from(textStream(), 'utf8');
  let client = '';
  for (let i = 0; i < wire.length; i += 7) {
    const out = translator.feed(wire.subarray(i, i + 7));
    if (out.length === 0) continue;
    extractor.feed(out);
    client += rewriter.feed(out).toString('utf8');
  }
  const tail = translator.finish();
  if (tail.length > 0) {
    extractor.feed(tail);
    client += rewriter.feed(tail).toString('utf8');
  }
  client += rewriter.finish().toString('utf8');

  // Billing input: the additive numbers VERBATIM (input EXCLUDES the cache
  // buckets — hp's settle folds them under the 'additive' convention and
  // prices the write bucket at its 1.25x premium), plus the DATED wire echo
  // for the served-model tripwire.
  const usage = extractor.finish();
  assert.equal(usage.model, 'claude-sonnet-4-6-20250514');
  assert.equal(usage.inputTokens, 3);
  assert.equal(usage.outputTokens, 5); // message_delta's cumulative count wins
  assert.equal(usage.cacheReadTokens, 7907);
  assert.equal(usage.cacheWriteTokens, 12);
  assert.equal(usage.totalCost, 0); // priced from the catalog, never the stream

  // Client side: chat-shaped chunks, public slug, no bare wire id.
  assert.ok(client.includes('"model":"anthropic/claude-sonnet-4.6"'));
  assert.ok(!client.includes('"claude-sonnet-4-6"'));
  const frames = client
    .split('\n\n')
    .filter((f) => f.startsWith('data: '))
    .map((f) => f.slice(6));
  assert.equal(frames[frames.length - 1], '[DONE]');
  const parsed = frames.slice(0, -1).map((f) => JSON.parse(f));
  const text = parsed
    .flatMap((c) => c.choices ?? [])
    .map((c) => c.delta?.content ?? '')
    .join('');
  assert.equal(text, 'It is sunny.');
  const finish = parsed.find((c) => c.choices?.[0]?.finish_reason);
  assert.equal(finish.choices[0].finish_reason, 'stop');
});

test('tool_use blocks become chat tool_calls deltas; finish_reason maps tool_calls', () => {
  const stream = [
    sse({
      type: 'message_start',
      message: { id: 'm', model: 'claude-sonnet-4-6', usage: { input_tokens: 9, output_tokens: 1 } },
    }),
    sse({
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 'toolu_9', name: 'get_weather', input: {} },
    }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"city":' } }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '"Lisbon"}' } }),
    sse({ type: 'content_block_stop', index: 0 }),
    sse({ type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 30 } }),
    sse({ type: 'message_stop' }),
  ].join('');

  const out = new MessagesToChatSse({ upstreamModel: 'claude-sonnet-4-6' })
    .feed(Buffer.from(stream))
    .toString('utf8');
  const parsed = out
    .split('\n\n')
    .filter((f) => f.startsWith('data: ') && !f.includes('[DONE]'))
    .map((f) => JSON.parse(f.slice(6)));

  const start = parsed.find((c) => c.choices?.[0]?.delta?.tool_calls?.[0]?.id === 'toolu_9');
  assert.equal(start.choices[0].delta.tool_calls[0].function.name, 'get_weather');
  const args = parsed
    .flatMap((c) => c.choices ?? [])
    .flatMap((c) => c.delta?.tool_calls ?? [])
    .map((t) => t.function?.arguments ?? '')
    .join('');
  assert.equal(args, '{"city":"Lisbon"}');
  const finish = parsed.find((c) => c.choices?.[0]?.finish_reason);
  assert.equal(finish.choices[0].finish_reason, 'tool_calls');
});

test('stop-reason map: max_tokens → length; thinking deltas are dropped silently', () => {
  const stream = [
    sse({ type: 'message_start', message: { id: 'm', model: 'x', usage: { input_tokens: 1 } } }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'hmm' } }),
    sse({ type: 'message_delta', delta: { stop_reason: 'max_tokens' }, usage: { output_tokens: 2 } }),
    sse({ type: 'message_stop' }),
  ].join('');
  const out = new MessagesToChatSse({ upstreamModel: 'x' }).feed(Buffer.from(stream)).toString('utf8');
  assert.match(out, /"finish_reason":"length"/);
  assert.ok(!out.includes('hmm'));
});

test('error events and malformed frames become terminal error frames', () => {
  const errored = new MessagesToChatSse({ upstreamModel: 'm' });
  const out = errored
    .feed(Buffer.from(sse({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } })))
    .toString('utf8');
  assert.match(out, /"error"/);
  assert.match(out, /Overloaded/);
  // Goes silent after a fatal frame.
  assert.equal(
    errored.feed(Buffer.from(sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'x' } }))).length,
    0,
  );
  assert.equal(errored.finish().length, 0);

  const garbled = new MessagesToChatSse({ upstreamModel: 'm' });
  assert.match(garbled.feed(Buffer.from('data: {not json}\n\n')).toString('utf8'), /"error"/);
});

test('a stream ended before message_stop surfaces an error, not a fake completion', () => {
  const translator = new MessagesToChatSse({ upstreamModel: 'm' });
  translator.feed(
    Buffer.from(sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'partial' } })),
  );
  const tail = translator.finish().toString('utf8');
  assert.match(tail, /"error"/);
  assert.match(tail, /ended unexpectedly/);
  assert.ok(!tail.includes('[DONE]'));
});

// ---------------------------------------------------------------------------
// reasoning_effort → thinking (PPQdotAI #2646 step 2)
// ---------------------------------------------------------------------------

const thinkingBase = (extra = {}) => ({
  model: 'claude-haiku-4-5',
  messages: [{ role: 'user', content: 'hi' }],
  stream: true,
  ...extra,
});

test('reasoning_effort is mappable (no longer skips the candidate)', () => {
  assert.ok(ANTHROPIC_MAPPABLE_FIELDS.has('reasoning_effort'));
  const out = toMessagesRequest(thinkingBase({ reasoning_effort: 'medium' }));
  assert.equal(out.skip, undefined);
});

test('effort maps to a thinking budget', () => {
  for (const [effort, budget] of [['low', 1024], ['medium', 4096], ['high', 16384]]) {
    const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: effort }));
    assert.deepEqual(body.thinking, { type: 'enabled', budget_tokens: budget });
  }
});

test("OpenAI's 'minimal' maps to the floor", () => {
  const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: 'minimal' }));
  assert.equal(body.thinking.budget_tokens, 1024);
});

test('max_tokens is raised to fit the budget when the client did not set one', () => {
  const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: 'high' }));
  // budget must be strictly less than max_tokens
  assert.ok(body.max_tokens > body.thinking.budget_tokens, 'max_tokens must exceed budget');
  assert.equal(body.max_tokens, 16384 + 2048);
});

test('a client-supplied max_tokens is respected; the budget clamps into it', () => {
  const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: 'high', max_tokens: 8192 }));
  assert.equal(body.max_tokens, 8192, 'client limit must not be overridden');
  assert.equal(body.thinking.budget_tokens, 8192 - 2048);
  assert.ok(body.thinking.budget_tokens < body.max_tokens);
});

test('too little headroom leaves thinking off rather than sending a sub-floor budget', () => {
  const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: 'high', max_tokens: 2500 }));
  assert.equal(body.thinking, undefined);
  assert.equal(body.max_tokens, 2500);
});

test('sampling knobs are dropped while thinking is on, kept while it is off', () => {
  const on = toMessagesRequest(
    thinkingBase({ reasoning_effort: 'medium', temperature: 0.7, top_p: 0.9, top_k: 40 }),
  ).body;
  assert.equal(on.temperature, undefined, 'Anthropic requires temperature=1 with thinking');
  assert.equal(on.top_p, undefined);
  assert.equal(on.top_k, undefined);

  const off = toMessagesRequest(thinkingBase({ temperature: 0.7, top_p: 0.9, top_k: 40 })).body;
  assert.equal(off.temperature, 0.7);
  assert.equal(off.top_p, 0.9);
  assert.equal(off.top_k, 40);
});

test('an unknown effort value leaves thinking off', () => {
  const { body } = toMessagesRequest(thinkingBase({ reasoning_effort: 'turbo' }));
  assert.equal(body.thinking, undefined);
});

// ---------------------------------------------------------------------------
// Adaptive-only models reject an explicit budget (mirrors hp's
// ADAPTIVE_ONLY_THINKING, live-probed 2026-08-18)
// ---------------------------------------------------------------------------

const ADAPTIVE_IDS = [
  'claude-fable-5',
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-sonnet-5',
];

test('adaptive-only models get thinking:{type:adaptive} + output_config.effort', () => {
  for (const model of ADAPTIVE_IDS) {
    const { body } = toMessagesRequest({
      model,
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
      reasoning_effort: 'medium',
    });
    assert.deepEqual(body.thinking, { type: 'adaptive' }, model);
    assert.equal(body.output_config?.effort, 'medium', model);
    assert.equal(body.thinking.budget_tokens, undefined, `${model} must not carry a budget`);
  }
});

test('budget-accepting models keep the explicit budget form', () => {
  const { body } = toMessagesRequest({
    model: 'claude-sonnet-4-6',
    messages: [{ role: 'user', content: 'hi' }],
    stream: true,
    reasoning_effort: 'medium',
  });
  assert.deepEqual(body.thinking, { type: 'enabled', budget_tokens: 4096 });
  assert.equal(body.output_config, undefined);
});

test('effort tiers map onto the effort dial ordinally', () => {
  for (const [effort, dial] of [['low', 'low'], ['medium', 'medium'], ['high', 'high']]) {
    const { body } = toMessagesRequest({
      model: 'claude-opus-5',
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
      reasoning_effort: effort,
    });
    assert.equal(body.output_config.effort, dial, effort);
  }
});

test('adaptive path still drops the sampling knobs', () => {
  const { body } = toMessagesRequest({
    model: 'claude-opus-5',
    messages: [{ role: 'user', content: 'hi' }],
    stream: true,
    reasoning_effort: 'high',
    temperature: 0.7,
  });
  assert.equal(body.temperature, undefined);
});
