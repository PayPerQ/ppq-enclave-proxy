import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BEDROCK_MAPPABLE_FIELDS,
  toResponsesRequest,
  buildBedrockRequest,
  ResponsesToChatSse,
} from '../src/bedrock.mjs';
import { CostExtractor } from '../src/cost.mjs';
import { directResponseRewriter } from '../src/rebrand.mjs';

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
    temperature: 0.7,
    top_p: 0.9,
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

test('non-streaming requests skip; empty conversations skip', () => {
  assert.equal(toResponsesRequest(projected({ stream: undefined })).skip, 'bedrock_stream_only');
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
