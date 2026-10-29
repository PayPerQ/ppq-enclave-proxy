import { test } from 'node:test';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
import assert from 'node:assert/strict';
import {
  BEDROCK_MAPPABLE_FIELDS,
  toResponsesRequest,
  buildBedrockRequest,
  buildOpenAIResponsesRequest,
  ResponsesToChatSse,
  ResponsesJsonToChat,
  responsesJsonToChatCompletion,
  MAX_JSON_BODY_BYTES,
} from '../src/bedrock.mjs';
import { CostExtractor } from '../src/cost.mjs';
import { RESPONSES_MIN_MAX_OUTPUT_TOKENS } from '../src/eligibility.mjs';
import { directResponseRewriter, ModelKeyRewriter } from '../src/rebrand.mjs';

// ---------------------------------------------------------------------------
// Fixtures — endpoint + ids per the 2026-08-14 live probe (horse-power
// services/directProviders/bedrockUsage.fixtures.json).
// ---------------------------------------------------------------------------

const CANDIDATE = {
  provider: 'bedrock',
  api_style: 'bedrock',
  host: 'bedrock-mantle.us-east-2.api.aws',
  path: '/openai/v1/responses',
  region: 'us-east-2',
  key_ref: 'bedrock',
  upstream_model: 'openai.gpt-5.5',
  or_slug: 'openai/gpt-5.5',
  supports_tools: true,
  supports_image_input: false,
  context_length: 272000,
};

const PORTS = { 'bedrock-mantle.us-east-2.api.aws': 9446 };
const CREDS = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
  sessionToken: 'FwoEXAMPLETOKEN',
};

function basePayload(overrides = {}) {
  return {
    model: 'openai/gpt-5.5',
    stream: true,
    messages: [{ role: 'user', content: 'hello' }],
    ...overrides,
  };
}

// projectAllowedFields output shape, hand-rolled for direct toResponsesRequest tests.
function projected(overrides = {}) {
  return {
    model: 'openai.gpt-5.5',
    stream: true,
    stream_options: { include_usage: true },
    messages: [{ role: 'user', content: 'hello' }],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// toResponsesRequest
// ---------------------------------------------------------------------------

test('maps a full conversation to Responses input items', () => {
  const out = toResponsesRequest(
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
      parallel_tool_calls: false,
    }),
  );

  assert.equal(out.skip, undefined);
  assert.deepEqual(out.body, {
    model: 'openai.gpt-5.5',
    input: [
      { role: 'system', content: [{ type: 'input_text', text: 'be terse' }] },
      { role: 'user', content: [{ type: 'input_text', text: 'weather in Lisbon?' }] },
      {
        type: 'function_call',
        call_id: 'call_1',
        name: 'get_weather',
        arguments: '{"city":"Lisbon"}',
      },
      { type: 'function_call_output', call_id: 'call_1', output: '{"temp_c":21}' },
      { role: 'user', content: [{ type: 'input_text', text: 'and tomorrow?' }] },
    ],
    stream: true,
    // Privacy: the Responses API PERSISTS by default; the enclave always opts out.
    store: false,
    max_output_tokens: 512,
    // temperature / top_p are consumed, never forwarded (the frontier models
    // 400 on them; OpenRouter drops them too — probed 2026-09-10).
    parallel_tool_calls: false,
    tools: [
      {
        type: 'function',
        name: 'get_weather',
        parameters: { type: 'object', properties: { city: { type: 'string' } } },
        strict: false,
        description: 'Weather lookup',
      },
    ],
    tool_choice: 'auto',
  });
});

test('assistant text turns become output_text items', () => {
  const out = toResponsesRequest(
    projected({
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: 'hello there' },
        { role: 'user', content: 'again' },
      ],
    }),
  );
  assert.deepEqual(out.body.input[1], {
    role: 'assistant',
    content: [{ type: 'output_text', text: 'hello there' }],
  });
});

test('tool_choice mappings: none/required pass through, named form flattens', () => {
  const tools = [{ type: 'function', function: { name: 'f', parameters: {} } }];
  assert.equal(toResponsesRequest(projected({ tools, tool_choice: 'none' })).body.tool_choice, 'none');
  assert.equal(
    toResponsesRequest(projected({ tools, tool_choice: 'required' })).body.tool_choice,
    'required',
  );
  assert.deepEqual(
    toResponsesRequest(
      projected({ tools, tool_choice: { type: 'function', function: { name: 'f' } } }),
    ).body.tool_choice,
    { type: 'function', name: 'f' },
  );
});

test('max_completion_tokens wins; reasoning_effort rides reasoning.effort', () => {
  const out = toResponsesRequest(
    projected({ max_tokens: 100, max_completion_tokens: 200, reasoning_effort: 'high' }),
  );
  assert.equal(out.body.max_output_tokens, 200);
  assert.deepEqual(out.body.reasoning, { effort: 'high' });
});

test('unmappable projected fields skip the candidate with the field named', () => {
  for (const [field, value] of [
    ['response_format', { type: 'json_object' }],
    ['stop', 'END'], // the Responses API has no stop sequences
    ['seed', 42],
    ['frequency_penalty', 0.5],
    ['logit_bias', { 50256: -100 }],
    ['n', 2],
    ['top_k', 40],
  ]) {
    const out = toResponsesRequest(projected({ [field]: value }));
    assert.equal(out.skip, 'bedrock_unmappable_field', field);
    assert.equal(out.offendingField, field);
  }
});

test('service_tier: API-valid values forward, foreign values skip the candidate', () => {
  // Row-originated (never client input); mantle's Responses API accepts
  // auto/default/flex/priority (probe recorded defaultServiceTier 'auto').
  const ok = toResponsesRequest(projected({ service_tier: 'priority' }));
  assert.equal(ok.skip, undefined);
  assert.equal(ok.body.service_tier, 'priority');

  const foreign = toResponsesRequest(projected({ service_tier: 'standard_only' }));
  assert.equal(foreign.skip, 'bedrock_unmappable_field');
  assert.equal(foreign.offendingField, 'service_tier');
});

test('a max-tokens cap under the Responses minimum skips on the caller’s own field, never a 400 (horse-power #1173)', () => {
  assert.equal(RESPONSES_MIN_MAX_OUTPUT_TOKENS, 16);
  const low = toResponsesRequest(projected({ max_tokens: 5 }));
  assert.deepEqual([low.skip, low.offendingField], ['bedrock_unmappable_field', 'max_tokens']);
  const lowCompletion = toResponsesRequest(projected({ max_completion_tokens: 15, max_tokens: 100 }));
  assert.deepEqual([lowCompletion.skip, lowCompletion.offendingField], ['bedrock_unmappable_field', 'max_completion_tokens']);
  // A null max_completion_tokens falls through to max_tokens — the named field follows the value that was read.
  const nullCompletion = toResponsesRequest(projected({ max_completion_tokens: null, max_tokens: 5 }));
  assert.deepEqual([nullCompletion.skip, nullCompletion.offendingField], ['bedrock_unmappable_field', 'max_tokens']);
  assert.equal(toResponsesRequest(projected({ max_tokens: 16 })).body.max_output_tokens, 16);
});

test('non-streaming requests ride the wire with stream:false (horse-power #1159); empty conversations skip', () => {
  assert.equal(toResponsesRequest(projected({ stream: undefined })).body.stream, false);
  assert.equal(toResponsesRequest(projected({ stream: false })).body.stream, false);
  assert.equal(toResponsesRequest(projected({ stream: true })).body.stream, true);
  assert.equal(
    toResponsesRequest(projected({ messages: [] })).skip,
    'bedrock_unmappable_field',
  );
});

test('every mappable field is either consumed or expressed — the set matches the adapter', () => {
  const out = toResponsesRequest(
    projected({
      temperature: 1,
      top_p: 0.5,
      max_tokens: 10,
      max_completion_tokens: 20,
      tools: [{ type: 'function', function: { name: 'f', parameters: {} } }],
      tool_choice: 'auto',
      parallel_tool_calls: true,
      reasoning_effort: 'low',
      user: 'ppq-hash',
    }),
  );
  assert.equal(out.skip, undefined);
  assert.equal(BEDROCK_MAPPABLE_FIELDS.has('messages'), true);
  // `user` is consumed, never forwarded — mantle has no equivalent.
  assert.equal(out.body.user, undefined);
  // Sampling knobs are consumed too: never on the wire (mirror of hp).
  assert.equal(out.body.temperature, undefined);
  assert.equal(out.body.top_p, undefined);
});

// ---------------------------------------------------------------------------
// buildBedrockRequest
// ---------------------------------------------------------------------------

test('builds a SigV4-signed mantle Responses request through the vsock tunnel mouth', () => {
  const built = buildBedrockRequest({
    candidate: CANDIDATE,
    basePayload: basePayload(),
    ports: PORTS,
    creds: CREDS,
    now: new Date('2026-08-14T12:00:00Z'),
  });

  assert.equal(built.skip, undefined);
  assert.equal(built.provider, 'bedrock');
  assert.equal(built.orSlug, 'openai/gpt-5.5');
  assert.equal(built.upstreamModel, 'openai.gpt-5.5');
  assert.equal(built.apiStyle, 'bedrock');

  const { opts, bodyStr } = built;
  assert.equal(opts.host, '127.0.0.1');
  assert.equal(opts.port, 9446);
  assert.equal(opts.servername, CANDIDATE.host); // E2E TLS pin to the real host
  assert.equal(opts.path, '/openai/v1/responses');
  assert.equal(opts.headers.host, CANDIDATE.host);
  assert.equal(opts.headers.accept, 'text/event-stream');
  assert.equal(opts.headers['content-length'], Buffer.byteLength(bodyStr));
  // Probed: the scope's service name is bedrock-mantle, NOT bedrock.
  assert.match(
    opts.headers.authorization,
    /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20260814\/us-east-2\/bedrock-mantle\/aws4_request/,
  );
  assert.equal(opts.headers['x-amz-security-token'], CREDS.sessionToken);

  // The signed body is the Responses translation: model in the BODY, store off.
  const body = JSON.parse(bodyStr);
  assert.equal(body.model, 'openai.gpt-5.5');
  assert.equal(body.store, false);
  assert.deepEqual(body.input, [
    { role: 'user', content: [{ type: 'input_text', text: 'hello' }] },
  ]);
});

test('skips cleanly: no tunnel, no creds, expired creds, missing region', () => {
  const args = { candidate: CANDIDATE, basePayload: basePayload(), ports: PORTS, creds: CREDS };
  assert.equal(buildBedrockRequest({ ...args, ports: {} }).skip, 'no_tunnel_or_key');
  assert.equal(buildBedrockRequest({ ...args, creds: null }).skip, 'no_tunnel_or_key');
  assert.equal(
    buildBedrockRequest({
      ...args,
      creds: { ...CREDS, expiration: new Date(Date.now() + 30_000) },
    }).skip,
    'bedrock_creds_expired',
  );
  assert.equal(
    buildBedrockRequest({ ...args, candidate: { ...CANDIDATE, region: undefined } }).skip,
    'no_region',
  );
});

test('the SHARED eligibility gate still runs first (web search bails to OpenRouter)', () => {
  const built = buildBedrockRequest({
    candidate: CANDIDATE,
    basePayload: basePayload({ plugins: [{ id: 'web' }] }),
    ports: PORTS,
    creds: CREDS,
  });
  assert.equal(built.skip, 'web_search_requires_openrouter');
});

test('verbosity rides text.verbosity end to end on a bedrock candidate', () => {
  // Probed 2026-09-28 on gpt-6-luna: `text.verbosity` low/high → 200, echoed
  // back, output length follows it.
  assert.deepEqual(toResponsesRequest(projected({ verbosity: 'low' })).body.text, { verbosity: 'low' });

  const built = buildBedrockRequest({
    candidate: CANDIDATE,
    basePayload: basePayload({ verbosity: 'high' }),
    ports: PORTS,
    creds: CREDS,
  });
  assert.equal(built.skip, undefined);
  const sent = JSON.parse(built.bodyStr);
  assert.deepEqual(sent.text, { verbosity: 'high' });
  assert.equal(sent.verbosity, undefined);

  // An invalid value skips the candidate rather than 400ing upstream.
  const bad = buildBedrockRequest({
    candidate: CANDIDATE,
    basePayload: basePayload({ verbosity: 'loud' }),
    ports: PORTS,
    creds: CREDS,
  });
  assert.equal(bad.skip, 'unmappable_field');
  assert.equal(bad.offendingField, 'verbosity');
});

// ---------------------------------------------------------------------------
// ResponsesToChatSse — through the REAL CostExtractor + rewriter
// ---------------------------------------------------------------------------

const sse = (obj) => `event: ${obj.type}\ndata: ${JSON.stringify(obj)}\n\n`;

/**
 * The probed event sequence (fixtures `streaming.eventSequence`), with the
 * warm-cache Sol usage numbers on the terminal event.
 */
function textStream() {
  return [
    sse({ type: 'response.created', response: { id: 'resp_1', model: 'openai.gpt-5.5' } }),
    sse({ type: 'response.in_progress' }),
    sse({ type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1' } }),
    sse({ type: 'response.content_part.added', item_id: 'msg_1' }),
    sse({ type: 'response.output_text.delta', item_id: 'msg_1', delta: 'It is ' }),
    sse({ type: 'response.output_text.delta', item_id: 'msg_1', delta: 'sunny.' }),
    sse({ type: 'response.output_text.done', item_id: 'msg_1', text: 'It is sunny.' }),
    sse({ type: 'response.content_part.done', item_id: 'msg_1' }),
    sse({ type: 'response.output_item.done', output_index: 0 }),
    sse({
      type: 'response.completed',
      response: {
        id: 'resp_1',
        model: 'openai.gpt-5.5',
        status: 'completed',
        usage: {
          input_tokens: 11213,
          input_tokens_details: { cache_write_tokens: 0, cached_tokens: 11211 },
          output_tokens: 5,
          output_tokens_details: { reasoning_tokens: 0 },
          total_tokens: 11218,
        },
      },
    }),
  ].join('');
}

test('captures response.created\'s model echo before the first chat frame, for the receipt', () => {
  const translator = new ResponsesToChatSse({ upstreamModel: 'openai.gpt-5.5' });
  assert.equal(translator.wireModel, null);
  const first = translator.feed(Buffer.from(sse({ type: 'response.created', response: { id: 'resp_1', model: 'openai.gpt-5.5-2026-01-01' } }), 'utf8'));
  assert.ok(first.length > 0);
  assert.equal(translator.wireModel, 'openai.gpt-5.5-2026-01-01');
  assert.ok(first.toString('utf8').includes('"model":"openai.gpt-5.5"'), 'the frame keeps the configured id');
});

test('keeps a dissenting terminal echo apart from the first one', () => {
  const translator = new ResponsesToChatSse({ upstreamModel: 'openai.gpt-5.5' });
  translator.feed(Buffer.from(sse({ type: 'response.created', response: { id: 'r', model: 'openai.gpt-5.5-A' } }), 'utf8'));
  const out = translator.feed(Buffer.from(sse({
    type: 'response.completed',
    response: { id: 'r', model: 'openai.gpt-5.5-B', status: 'completed', usage: { input_tokens: 9, output_tokens: 5 } },
  }), 'utf8')).toString('utf8');
  assert.equal(translator.wireModel, 'openai.gpt-5.5-A', 'the first echo is what the receipt was signed with');
  assert.equal(translator.terminalModel, 'openai.gpt-5.5-B', 'the terminal echo is recorded, not merged');
  // The usage frame still carries the terminal echo VERBATIM, as before.
  assert.ok(out.includes('"model":"openai.gpt-5.5-B"'));
});

test('translates the probed Responses stream into chat SSE the existing pipeline understands', () => {
  const translator = new ResponsesToChatSse({ upstreamModel: 'openai.gpt-5.5' });
  const extractor = new CostExtractor({ isFreeModel: false });
  const rewriter = directResponseRewriter('openai.gpt-5.5', 'openai/gpt-5.5');

  // Feed with ugly fragmentation: 7-byte strides across the whole stream.
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

  // The extractor (billing input) saw the WIRE model id + subset usage,
  // VERBATIM from the probe fixture — cache buckets stay subsets of input.
  const usage = extractor.finish();
  assert.equal(usage.model, 'openai.gpt-5.5');
  assert.equal(usage.inputTokens, 11213);
  assert.equal(usage.outputTokens, 5);
  assert.equal(usage.cacheReadTokens, 11211);
  assert.equal(usage.cacheWriteTokens, 0);
  assert.equal(usage.totalCost, 0); // priced from the catalog, never the stream

  // The CLIENT never saw the wire id, and got well-formed chat chunks.
  assert.ok(!client.includes('"openai.gpt-5.5"'));
  assert.ok(client.includes('"model":"openai/gpt-5.5"'));
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

test('function-call events become chat tool_calls deltas (Responses spec — unprobed on mantle)', () => {
  const stream = [
    sse({ type: 'response.created', response: { id: 'r', model: 'm' } }),
    sse({
      type: 'response.output_item.added',
      output_index: 0,
      item: { type: 'function_call', id: 'fc_1', call_id: 'call_9', name: 'get_weather' },
    }),
    sse({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', delta: '{"city":' }),
    sse({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', delta: '"Lisbon"}' }),
    sse({
      type: 'response.completed',
      response: { id: 'r', model: 'm', status: 'completed', usage: { input_tokens: 9, output_tokens: 5 } },
    }),
  ].join('');

  const translator = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out = translator.feed(Buffer.from(stream)).toString('utf8');

  const parsed = out
    .split('\n\n')
    .filter((f) => f.startsWith('data: ') && !f.includes('[DONE]'))
    .map((f) => JSON.parse(f.slice(6)));

  const start = parsed.find((c) => c.choices?.[0]?.delta?.tool_calls?.[0]?.id === 'call_9');
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

test('terminal argument events backfill only what the deltas never carried', () => {
  const fc = { type: 'function_call', id: 'fc_1', call_id: 'call_9', name: 'get_weather' };
  const stream = [
    sse({ type: 'response.created', response: { id: 'r', model: 'm' } }),
    sse({ type: 'response.output_item.added', output_index: 0, item: fc }),
    sse({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', delta: '{"city":' }),
    // .done repeats the COMPLETE string — only the un-streamed suffix flows.
    sse({ type: 'response.function_call_arguments.done', item_id: 'fc_1', arguments: '{"city":"Lisbon"}' }),
    // output_item.done repeats it AGAIN — a fully-delivered call adds nothing.
    sse({ type: 'response.output_item.done', output_index: 0, item: { ...fc, arguments: '{"city":"Lisbon"}' } }),
    sse({
      type: 'response.completed',
      response: { id: 'r', model: 'm', status: 'completed', usage: { input_tokens: 9, output_tokens: 5 } },
    }),
  ].join('');

  const translator = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out = translator.feed(Buffer.from(stream)).toString('utf8');
  const argChunks = out
    .split('\n\n')
    .filter((f) => f.startsWith('data: ') && !f.includes('[DONE]'))
    .map((f) => JSON.parse(f.slice(6)))
    .map((c) => c.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments)
    .filter((a) => typeof a === 'string');
  assert.deepEqual(argChunks, ['', '{"city":', '"Lisbon"}']);
});

test('arguments arriving ONLY in the terminal event still deliver; contradictions are dropped', () => {
  const fc = { type: 'function_call', id: 'fc_1', call_id: 'call_9', name: 'get_weather' };
  const onlyTerminal = [
    sse({ type: 'response.created', response: { id: 'r', model: 'm' } }),
    sse({ type: 'response.output_item.added', output_index: 0, item: fc }),
    sse({ type: 'response.output_item.done', output_index: 0, item: { ...fc, arguments: '{"city":"Lisbon"}' } }),
    sse({
      type: 'response.completed',
      response: { id: 'r', model: 'm', status: 'completed', usage: { input_tokens: 9, output_tokens: 5 } },
    }),
  ].join('');
  const t1 = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out1 = t1.feed(Buffer.from(onlyTerminal)).toString('utf8');
  const args1 = out1
    .split('\n\n')
    .filter((f) => f.startsWith('data: ') && !f.includes('[DONE]'))
    .map((f) => JSON.parse(f.slice(6)))
    .flatMap((c) => c.choices ?? [])
    .flatMap((c) => c.delta?.tool_calls ?? [])
    .map((t) => t.function?.arguments ?? '')
    .join('');
  assert.equal(args1, '{"city":"Lisbon"}');

  // A terminal string that contradicts the streamed prefix must not splice.
  const contradicted = [
    sse({ type: 'response.created', response: { id: 'r', model: 'm' } }),
    sse({ type: 'response.output_item.added', output_index: 0, item: fc }),
    sse({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', delta: '{"town":' }),
    sse({ type: 'response.function_call_arguments.done', item_id: 'fc_1', arguments: '{"city":"Lisbon"}' }),
    sse({
      type: 'response.completed',
      response: { id: 'r', model: 'm', status: 'completed', usage: { input_tokens: 9, output_tokens: 5 } },
    }),
  ].join('');
  const t2 = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out2 = t2.feed(Buffer.from(contradicted)).toString('utf8');
  const args2 = out2
    .split('\n\n')
    .filter((f) => f.startsWith('data: ') && !f.includes('[DONE]'))
    .map((f) => JSON.parse(f.slice(6)))
    .map((c) => c.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments)
    .filter((a) => typeof a === 'string');
  assert.deepEqual(args2, ['', '{"town":']);
});

test('response.incomplete with max_output_tokens maps to finish_reason length', () => {
  const stream = [
    sse({ type: 'response.created', response: {} }),
    sse({
      type: 'response.incomplete',
      response: {
        status: 'incomplete',
        incomplete_details: { reason: 'max_output_tokens' },
        usage: { input_tokens: 9, output_tokens: 5 },
      },
    }),
  ].join('');
  const out = new ResponsesToChatSse({ upstreamModel: 'm' }).feed(Buffer.from(stream)).toString('utf8');
  assert.match(out, /"finish_reason":"length"/);
  assert.match(out, /\[DONE\]/);
});

test('response.failed and malformed frames become terminal error frames', () => {
  const failed = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out = failed
    .feed(
      Buffer.from(
        sse({ type: 'response.failed', response: { error: { message: 'throttled upstream' } } }),
      ),
    )
    .toString('utf8');
  assert.match(out, /"error"/);
  assert.match(out, /throttled upstream/);
  // After a fatal frame the transform goes silent.
  assert.equal(failed.feed(Buffer.from(sse({ type: 'response.output_text.delta', delta: 'x' }))).length, 0);
  assert.equal(failed.finish().length, 0);

  const garbled = new ResponsesToChatSse({ upstreamModel: 'm' });
  const out2 = garbled.feed(Buffer.from('data: {not json}\n\n')).toString('utf8');
  assert.match(out2, /"error"/);
});

test('a stream ended before response.completed surfaces an error, not a fake completion', () => {
  const translator = new ResponsesToChatSse({ upstreamModel: 'm' });
  translator.feed(Buffer.from(sse({ type: 'response.output_text.delta', delta: 'partial' })));
  const tail = translator.finish().toString('utf8');
  assert.match(tail, /"error"/);
  assert.match(tail, /ended unexpectedly/);
  assert.ok(!tail.includes('[DONE]'));
});

// ---------------------------------------------------------------------------
// image parts (probed 2026-09-10: input_image data URIs → 200 on every seeded
// model; mirror of hp bedrockChatTranslator.ts)
// ---------------------------------------------------------------------------

const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

test('image: a user turn of text + image maps to input_text + input_image items, in order', () => {
  const out = toResponsesRequest(
    projected({
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'What ' },
            { type: 'text', text: 'is this?' },
            { type: 'image_url', image_url: { url: PNG, detail: 'high' } },
            { type: 'text', text: 'One word.' },
          ],
        },
      ],
    }),
  );
  assert.equal(out.skip, undefined);
  assert.deepEqual(out.body.input, [
    {
      role: 'user',
      content: [
        // Adjacent text parts join into one item (pre-image byte parity).
        { type: 'input_text', text: 'What is this?' },
        // `detail` is not forwarded (API default applies).
        { type: 'input_image', image_url: PNG },
        { type: 'input_text', text: 'One word.' },
      ],
    },
  ]);
});

test('image: a text-only user turn projects exactly as before images were admitted', () => {
  const out = toResponsesRequest(
    projected({ messages: [{ role: 'user', content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] }] }),
  );
  assert.deepEqual(out.body.input, [{ role: 'user', content: [{ type: 'input_text', text: 'ab' }] }]);
});

test("image: media set = the gate's minus heic/heif — heic/heif skip, webp/jpeg map, gif never listed", () => {
  for (const type of ['heic', 'heif']) {
    const out = toResponsesRequest(
      projected({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:image/${type};base64,AAAA` } }] }] }),
    );
    assert.equal(out.skip, 'bedrock_unmappable_field', type);
    assert.equal(out.offendingField, 'messages.content');
  }
  for (const type of ['webp', 'jpeg']) {
    const out = toResponsesRequest(
      projected({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:image/${type};base64,AAAA` } }] }] }),
    );
    assert.equal(out.skip, undefined, type);
    assert.deepEqual(out.body.input[0].content, [{ type: 'input_image', image_url: `data:image/${type};base64,AAAA` }]);
  }
  // gif: the shared gate never admits it (non_text_content at the gate), so
  // the adapter must not claim it either — the two sets stay equal minus
  // heic/heif. Checked end-to-end so a gate change would surface here.
  const gif = toResponsesRequest(
    projected({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'data:image/gif;base64,AAAA' } }] }] }),
  );
  assert.equal(gif.skip, 'bedrock_unmappable_field');
  const gated = buildBedrockRequest({
    candidate: { ...CANDIDATE, supports_image_input: true },
    basePayload: basePayload({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'data:image/gif;base64,AAAA' } }] }] }),
    ports: PORTS,
    creds: CREDS,
    now: new Date('2026-08-14T12:00:00Z'),
  });
  assert.equal(gated.skip, 'non_text_content');
});

test('image: malformed data URIs and https URLs skip the candidate', () => {
  for (const url of ['data:...', 'https://example.com/cat.png']) {
    const out = toResponsesRequest(
      projected({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url } }] }] }),
    );
    assert.equal(out.skip, 'bedrock_unmappable_field', url);
    assert.equal(out.offendingField, 'messages.content');
  }
});

test('image: on any non-user turn skips — only user turns are cleared for images', () => {
  for (const role of ['assistant', 'system', 'developer', 'tool']) {
    const out = toResponsesRequest(
      projected({
        messages: [
          { role: 'user', content: 'hi' },
          { role, tool_call_id: 'c1', content: [{ type: 'image_url', image_url: { url: PNG } }] },
        ],
      }),
    );
    assert.equal(out.skip, 'bedrock_unmappable_field', role);
    assert.equal(out.offendingField, 'messages.content');
  }
});

test('image: end-to-end through buildBedrockRequest on an image-capable candidate', () => {
  const built = buildBedrockRequest({
    candidate: { ...CANDIDATE, supports_image_input: true },
    basePayload: basePayload({ messages: [{ role: 'user', content: [{ type: 'text', text: 'color?' }, { type: 'image_url', image_url: { url: PNG } }] }] }),
    ports: PORTS,
    creds: CREDS,
    now: new Date('2026-08-14T12:00:00Z'),
  });
  assert.equal(built.skip, undefined);
  const body = JSON.parse(built.bodyStr);
  assert.deepEqual(body.input[0].content[1], { type: 'input_image', image_url: PNG });
  // …and without image support on the candidate the shared gate still bails.
  const bail = buildBedrockRequest({
    candidate: { ...CANDIDATE, supports_image_input: false },
    basePayload: basePayload({ messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: PNG } }] }] }),
    ports: PORTS,
    creds: CREDS,
    now: new Date('2026-08-14T12:00:00Z'),
  });
  assert.equal(bail.skip, 'non_text_content');
});

// ---------------------------------------------------------------------------
// buildOpenAIResponsesRequest — the Bearer twin (horse-power #1156)
// ---------------------------------------------------------------------------

const OPENAI_CANDIDATE = {
  provider: 'openai',
  api_style: 'openai-responses',
  host: 'api.openai.com',
  path: '/v1/responses',
  key_ref: 'openai',
  upstream_model: 'gpt-5.5',
  or_slug: 'openai/gpt-5.5',
  supports_tools: true,
  supports_image_input: true,
  context_length: 1050000,
};
const OPENAI_PORTS = { 'api.openai.com': 9459 };
const OPENAI_KEYS = { openai: 'sk-proj-test', openrouter: 'or-key' };

test('openai: builds the same Responses body as bedrock, posted to api.openai.com with the Bearer key', () => {
  const built = buildOpenAIResponsesRequest({
    candidate: OPENAI_CANDIDATE,
    basePayload: basePayload(),
    ports: OPENAI_PORTS,
    keys: OPENAI_KEYS,
  });
  assert.equal(built.skip, undefined);
  assert.equal(built.provider, 'openai');
  assert.equal(built.orSlug, 'openai/gpt-5.5');
  assert.equal(built.upstreamModel, 'gpt-5.5');
  assert.equal(built.apiStyle, 'openai-responses');

  const { opts, bodyStr } = built;
  assert.equal(opts.host, '127.0.0.1');
  assert.equal(opts.port, 9459);
  assert.equal(opts.servername, 'api.openai.com'); // E2E TLS pin to the real host
  assert.equal(opts.path, '/v1/responses');
  assert.equal(opts.headers.host, 'api.openai.com');
  assert.equal(opts.headers.accept, 'text/event-stream');
  assert.equal(opts.headers.authorization, 'Bearer sk-proj-test');
  assert.equal(opts.headers['x-amz-date'], undefined);
  assert.equal(opts.headers['content-length'], Buffer.byteLength(bodyStr));

  const body = JSON.parse(bodyStr);
  assert.equal(body.model, 'gpt-5.5'); // the bare OpenAI id from the candidate
  assert.equal(body.store, false);
  assert.equal(body.stream, true);
  assert.deepEqual(body.input, [{ role: 'user', content: [{ type: 'input_text', text: 'hello' }] }]);

  // Byte-identical translation to the bedrock builder for the same payload.
  const br = buildBedrockRequest({ candidate: CANDIDATE, basePayload: basePayload(), ports: PORTS, creds: CREDS });
  const brBody = JSON.parse(br.bodyStr);
  assert.deepEqual({ ...brBody, model: undefined }, { ...body, model: undefined });
});

test('openai: skips cleanly without a tunnel or key, and the SHARED gate still runs first', () => {
  const args = { candidate: OPENAI_CANDIDATE, basePayload: basePayload(), ports: OPENAI_PORTS, keys: OPENAI_KEYS };
  assert.equal(buildOpenAIResponsesRequest({ ...args, ports: {} }).skip, 'no_tunnel_or_key');
  assert.equal(buildOpenAIResponsesRequest({ ...args, keys: { openrouter: 'x' } }).skip, 'no_tunnel_or_key');
  assert.equal(
    buildOpenAIResponsesRequest({ ...args, basePayload: basePayload({ plugins: [{ id: 'web' }] }) }).skip,
    'web_search_requires_openrouter',
  );
  // hp's own OpenAI-family preference (#1111) is absorbed, not a skip.
  const pref = buildOpenAIResponsesRequest({
    ...args,
    basePayload: basePayload({ provider: { order: ['openai'], allow_fallbacks: true, ignore: ['amazon-bedrock'] } }),
  });
  assert.equal(pref.skip, undefined);
  assert.equal(JSON.parse(pref.bodyStr).provider, undefined);
  // The translator's unmappable fields skip the candidate with the field named.
  const stop = buildOpenAIResponsesRequest({ ...args, basePayload: basePayload({ stop: ['x'] }) });
  assert.equal(stop.skip, 'bedrock_unmappable_field');
  assert.equal(stop.offendingField, 'stop');
});

test('openai: temperature/top_p are dropped and reasoning_effort/verbosity/images ride the Responses body', () => {
  const built = buildOpenAIResponsesRequest({
    candidate: OPENAI_CANDIDATE,
    basePayload: basePayload({
      temperature: 0.3,
      top_p: 0.9,
      max_completion_tokens: 50,
      reasoning_effort: 'low',
      verbosity: 'low',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'colour?' },
            { type: 'image_url', image_url: { url: 'data:image/png;base64,iVBORw0KGgo=' } },
          ],
        },
      ],
    }),
    ports: OPENAI_PORTS,
    keys: OPENAI_KEYS,
  });
  assert.equal(built.skip, undefined, JSON.stringify(built));
  const body = JSON.parse(built.bodyStr);
  assert.equal(body.temperature, undefined);
  assert.equal(body.top_p, undefined);
  assert.equal(body.max_output_tokens, 50);
  assert.deepEqual(body.reasoning, { effort: 'low' });
  assert.deepEqual(body.text, { verbosity: 'low' });
  assert.deepEqual(body.input[0].content[1], { type: 'input_image', image_url: 'data:image/png;base64,iVBORw0KGgo=' });
});

test("openai: the dated snapshot echo (response.created) is the receipt's served model, and the rewriter hides the bare id", () => {
  const t = new ResponsesToChatSse({ upstreamModel: 'gpt-5.5' });
  const frames = [
    { type: 'response.created', response: { id: 'r', model: 'gpt-5.5-2026-04-23' } },
    { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'm' } },
    { type: 'response.output_text.delta', item_id: 'm', delta: 'pong' },
    {
      type: 'response.completed',
      response: {
        id: 'r',
        model: 'gpt-5.5-2026-04-23',
        usage: { input_tokens: 11, input_tokens_details: { cached_tokens: 0 }, output_tokens: 16, output_tokens_details: { reasoning_tokens: 9 }, total_tokens: 27 },
      },
    },
  ];
  const sse = frames.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join('');
  let out = t.feed(Buffer.from(sse)).toString() + t.finish().toString();
  assert.equal(t.wireModel, 'gpt-5.5-2026-04-23');
  // Chat chunks carry the candidate's upstream id, which the direct rewriter
  // maps to the public slug before the client sees it.
  const rw = directResponseRewriter('gpt-5.5', 'openai/gpt-5.5');
  out = rw.feed(Buffer.from(out)).toString() + rw.finish().toString();
  assert.ok(out.includes('"model":"openai/gpt-5.5"'), out);
  assert.ok(!out.includes('"model":"gpt-5.5"'), out);
});

test('openai: the per-end-user safety_identifier rides the direct body (HMAC of the authenticated credit id), never a caller value', () => {
  const { createHmac } = require('node:crypto');
  const args = { candidate: OPENAI_CANDIDATE, ports: OPENAI_PORTS, keys: OPENAI_KEYS, creditId: 'cred_123', safetySecret: 's3cret' };
  // A caller-supplied `user` is dropped by the translation; ours is set.
  const built = buildOpenAIResponsesRequest({ ...args, basePayload: basePayload({ user: 'attacker-chosen' }) });
  assert.equal(built.skip, undefined);
  const body = JSON.parse(built.bodyStr);
  assert.equal(body.safety_identifier, createHmac('sha256', 's3cret').update('cred_123').digest('hex'));
  assert.equal(body.user, undefined);
  // No secret, or no credit id: no identifier at all (the OpenRouter path's no-op).
  for (const partial of [{ safetySecret: '' }, { creditId: undefined }, { creditId: '' }]) {
    const b = JSON.parse(buildOpenAIResponsesRequest({ ...args, ...partial, basePayload: basePayload() }).bodyStr);
    assert.equal(b.safety_identifier, undefined, JSON.stringify(partial));
  }
  // The Bedrock builder is untouched: mantle has no equivalent field.
  const br = JSON.parse(buildBedrockRequest({ candidate: CANDIDATE, basePayload: basePayload(), ports: PORTS, creds: CREDS }).bodyStr);
  assert.equal(br.safety_identifier, undefined);
});

test('openai -pro candidate: the base model with reasoning.mode pro beside the caller’s effort (horse-power #1156)', () => {
  const pro = { ...OPENAI_CANDIDATE, upstream_model: 'gpt-6-astra', or_slug: 'openai/gpt-6-astra-pro', reasoning_mode: 'pro' };
  const withEffort = buildOpenAIResponsesRequest({ candidate: pro, basePayload: basePayload({ reasoning_effort: 'low' }), ports: OPENAI_PORTS, keys: OPENAI_KEYS });
  assert.equal(withEffort.skip, undefined);
  let body = JSON.parse(withEffort.bodyStr);
  assert.equal(body.model, 'gpt-6-astra');
  assert.deepEqual(body.reasoning, { effort: 'low', mode: 'pro' });
  const plain = buildOpenAIResponsesRequest({ candidate: pro, basePayload: basePayload(), ports: OPENAI_PORTS, keys: OPENAI_KEYS });
  body = JSON.parse(plain.bodyStr);
  assert.deepEqual(body.reasoning, { mode: 'pro' });
  // A plain candidate: no mode, whatever the caller sent in reasoning_effort.
  const none = buildOpenAIResponsesRequest({ candidate: OPENAI_CANDIDATE, basePayload: basePayload({ reasoning_effort: 'low' }), ports: OPENAI_PORTS, keys: OPENAI_KEYS });
  assert.deepEqual(JSON.parse(none.bodyStr).reasoning, { effort: 'low' });
});


// ── The usage frame speaks the CHAT names (horse-power #1159) ───────────────
test('the terminal usage frame carries prompt_tokens / completion_tokens (chat names), subset convention kept', () => {
  const translator = new ResponsesToChatSse({ upstreamModel: 'gpt-5.5' });
  const out = translator.feed(Buffer.from(sse({
    type: 'response.completed',
    response: { id: 'r', model: 'gpt-5.5-2026-04-23', status: 'completed', usage: { input_tokens: 20, output_tokens: 5, input_tokens_details: { cached_tokens: 8, cache_write_tokens: 2 }, output_tokens_details: { reasoning_tokens: 3 } } },
  }), 'utf8')).toString('utf8');
  const usageFrame = out.split('\n\n').map((f) => f.replace(/^data: /, '')).filter((f) => f && f !== '[DONE]').map((f) => JSON.parse(f)).find((c) => c.usage);
  assert.deepEqual(usageFrame.usage, {
    prompt_tokens: 20,
    completion_tokens: 5,
    total_tokens: 25,
    prompt_tokens_details: { cached_tokens: 8, cache_write_tokens: 2 },
    completion_tokens_details: { reasoning_tokens: 3 },
  });
  // cost.mjs reads the chat spelling as it read the Responses one.
  const extractor = new CostExtractor({ isFreeModel: false });
  extractor.feed(Buffer.from(out, 'utf8'));
  assert.equal(extractor.result.inputTokens, 20);
  assert.equal(extractor.result.outputTokens, 5);
  assert.equal(extractor.result.cacheReadTokens, 8);
  assert.equal(extractor.result.cacheWriteTokens, 2);
  assert.equal(extractor.result.reasoningTokens, 3);
});

// ── ResponsesJsonToChat: the non-streaming twin ─────────────────────────────
const JSON_ANSWER = {
  id: 'resp_j1', object: 'response', model: 'gpt-5.5-2026-04-23', status: 'completed',
  output: [{ type: 'reasoning', id: 'rs', summary: [] }, { type: 'message', id: 'm', role: 'assistant', content: [{ type: 'output_text', text: 'pong' }] }],
  usage: { input_tokens: 11, input_tokens_details: { cached_tokens: 0 }, output_tokens: 16, output_tokens_details: { reasoning_tokens: 9 }, total_tokens: 27 },
};

test('ResponsesJsonToChat buffers the one object and emits one chat.completion on finish(); wireModel for the receipt', () => {
  const t = new ResponsesJsonToChat({ upstreamModel: 'gpt-5.5' });
  assert.equal(t.contentType, 'application/json');
  assert.equal(t.streaming, false);
  const wire = Buffer.from(JSON.stringify(JSON_ANSWER), 'utf8');
  let mid = Buffer.alloc(0);
  for (let i = 0; i < wire.length; i += 5) mid = Buffer.concat([mid, t.feed(wire.subarray(i, i + 5))]);
  assert.equal(mid.length, 0, 'nothing goes out before the body is whole');
  const out = JSON.parse(t.finish().toString('utf8'));
  assert.equal(out.object, 'chat.completion');
  assert.equal(out.model, 'gpt-5.5-2026-04-23');
  assert.deepEqual(out.choices, [{ index: 0, message: { role: 'assistant', content: 'pong' }, finish_reason: 'stop' }]);
  assert.deepEqual(out.usage, { prompt_tokens: 11, completion_tokens: 16, total_tokens: 27, prompt_tokens_details: { cached_tokens: 0, cache_write_tokens: 0 }, completion_tokens_details: { reasoning_tokens: 9 } });
  assert.equal(t.wireModel, 'gpt-5.5-2026-04-23');
  assert.equal(t.failed, false);
  assert.equal(t.finish().length, 0, 'finish() is idempotent');
  // The extractor reads the JSON body as one line.
  const extractor = new CostExtractor({ isFreeModel: false });
  extractor.feed(Buffer.from(JSON.stringify(out), 'utf8'));
  extractor.feed(Buffer.from('\n', 'utf8'));
  assert.equal(extractor.result.inputTokens, 11);
  assert.equal(extractor.result.outputTokens, 16);
  assert.equal(extractor.result.model, 'gpt-5.5-2026-04-23');
  // The chat path's rewriter for this style maps the dated echo to the public slug on the client-bound bytes.
  const rewriter = new ModelKeyRewriter('gpt-5.5', 'openai/gpt-5.5');
  const shown = Buffer.concat([rewriter.feed(Buffer.from(JSON.stringify(out), 'utf8')), rewriter.finish()]).toString('utf8');
  assert.ok(shown.includes('"model":"openai/gpt-5.5"'), shown);
});

test('ResponsesJsonToChat: a failed object, garbage, or an over-cap body becomes the error envelope', () => {
  const failed = new ResponsesJsonToChat({ upstreamModel: 'gpt-5.5' });
  failed.feed(Buffer.from(JSON.stringify({ ...JSON_ANSWER, status: 'failed', error: { message: 'The server had an error' } })));
  assert.deepEqual(JSON.parse(failed.finish().toString('utf8')), { error: { message: 'upstream The server had an error', code: 502 } });
  assert.equal(failed.failed, true, 'the relay records the answer as an upstream failure');
  const garbage = new ResponsesJsonToChat({ upstreamModel: 'gpt-5.5' });
  garbage.feed(Buffer.from('{nope'));
  assert.deepEqual(JSON.parse(garbage.finish().toString('utf8')), { error: { message: 'upstream response body was not JSON', code: 502 } });
  assert.equal(garbage.wireModel, null);
  const big = new ResponsesJsonToChat({ upstreamModel: 'gpt-5.5' });
  big.feed(Buffer.alloc(MAX_JSON_BODY_BYTES, 0x20));
  big.feed(Buffer.from('{}'));
  assert.equal(big.chunks.length, 0, 'what it held is dropped at the cap');
  assert.deepEqual(JSON.parse(big.finish().toString('utf8')), { error: { message: 'upstream response body over the size cap', code: 502 } });
  assert.equal(garbage.failed, true);
  assert.equal(big.failed, true);
});

test('responsesJsonToChatCompletion: tool calls, cuts, refusal, fallbacks', () => {
  const tools = responsesJsonToChatCompletion({ ...JSON_ANSWER, output: [...JSON_ANSWER.output, { type: 'function_call', call_id: 'call_1', name: 'Bash', arguments: '{"command":"ls"}' }] }, { upstreamModel: 'gpt-5.5' });
  assert.equal(tools.choices[0].finish_reason, 'tool_calls');
  assert.deepEqual(tools.choices[0].message.tool_calls, [{ id: 'call_1', type: 'function', function: { name: 'Bash', arguments: '{"command":"ls"}' } }]);
  assert.equal(responsesJsonToChatCompletion({ ...JSON_ANSWER, status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } }, { upstreamModel: 'gpt-5.5' }).choices[0].finish_reason, 'length');
  const refused = responsesJsonToChatCompletion({ status: 'completed', output: [{ type: 'message', content: [{ type: 'refusal', refusal: 'no' }] }] }, { upstreamModel: 'gpt-5.5' });
  assert.deepEqual(refused.choices[0].message, { role: 'assistant', content: null, refusal: 'no' });
  assert.equal(refused.model, 'gpt-5.5', 'row id when the echo is missing');
  assert.equal(responsesJsonToChatCompletion([], { upstreamModel: 'gpt-5.5' }).error.code, 502);
});
