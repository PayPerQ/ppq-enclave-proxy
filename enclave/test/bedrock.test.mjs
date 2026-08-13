import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BEDROCK_MAPPABLE_FIELDS,
  toConverseRequest,
  buildBedrockRequest,
  EventStreamToSse,
} from '../src/bedrock.mjs';
import { encodeEventStreamMessage } from '../src/eventstream.mjs';
import { CostExtractor } from '../src/cost.mjs';
import { directResponseRewriter } from '../src/rebrand.mjs';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CANDIDATE = {
  provider: 'bedrock',
  api_style: 'bedrock',
  host: 'bedrock-runtime.us-east-2.amazonaws.com',
  path: '/model/us.openai.gpt-5.5-v1%3A0/converse-stream',
  region: 'us-east-2',
  key_ref: 'bedrock',
  upstream_model: 'us.openai.gpt-5.5-v1:0',
  or_slug: 'openai/gpt-5.5',
  supports_tools: true,
  supports_image_input: false,
  context_length: 400000,
};

const PORTS = { 'bedrock-runtime.us-east-2.amazonaws.com': 9446 };
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

// projectAllowedFields output shape, hand-rolled for direct toConverseRequest tests.
function projected(overrides = {}) {
  return {
    model: 'us.openai.gpt-5.5-v1:0',
    stream: true,
    stream_options: { include_usage: true },
    messages: [{ role: 'user', content: 'hello' }],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// toConverseRequest
// ---------------------------------------------------------------------------

test('maps a full conversation: system, tool round-trip, merging', () => {
  const out = toConverseRequest(
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
  assert.deepEqual(out.body, {
    // The tool result and the following user turn MERGE into one user message
    // (Converse requires strict user/assistant alternation), and the model id
    // is NOT in the body — it rides the URL path.
    messages: [
      { role: 'user', content: [{ text: 'weather in Lisbon?' }] },
      {
        role: 'assistant',
        content: [
          { toolUse: { toolUseId: 'call_1', name: 'get_weather', input: { city: 'Lisbon' } } },
        ],
      },
      {
        role: 'user',
        content: [
          { toolResult: { toolUseId: 'call_1', content: [{ text: '{"temp_c":21}' }] } },
          { text: 'and tomorrow?' },
        ],
      },
    ],
    system: [{ text: 'be terse' }],
    inferenceConfig: {
      maxTokens: 512,
      temperature: 0.7,
      topP: 0.9,
      stopSequences: ['END'],
    },
    toolConfig: {
      tools: [
        {
          toolSpec: {
            name: 'get_weather',
            inputSchema: { json: { type: 'object', properties: { city: { type: 'string' } } } },
            description: 'Weather lookup',
          },
        },
      ],
      toolChoice: { auto: {} },
    },
  });
});

test('tool_choice mappings: required → any, named → tool, none → no toolConfig', () => {
  const tools = [{ type: 'function', function: { name: 'f', parameters: {} } }];
  assert.deepEqual(
    toConverseRequest(projected({ tools, tool_choice: 'required' })).body.toolConfig.toolChoice,
    { any: {} },
  );
  assert.deepEqual(
    toConverseRequest(
      projected({ tools, tool_choice: { type: 'function', function: { name: 'f' } } }),
    ).body.toolConfig.toolChoice,
    { tool: { name: 'f' } },
  );
  assert.equal(
    toConverseRequest(projected({ tools, tool_choice: 'none' })).body.toolConfig,
    undefined,
  );
});

test('max_completion_tokens wins over max_tokens; reasoning_effort rides additionalModelRequestFields', () => {
  const out = toConverseRequest(
    projected({ max_tokens: 100, max_completion_tokens: 200, reasoning_effort: 'high' }),
  );
  assert.equal(out.body.inferenceConfig.maxTokens, 200);
  assert.deepEqual(out.body.additionalModelRequestFields, { reasoning_effort: 'high' });
});

test('unmappable projected fields skip the candidate with the field named', () => {
  for (const [field, value] of [
    ['response_format', { type: 'json_object' }],
    ['seed', 42],
    ['frequency_penalty', 0.5],
    ['logit_bias', { 50256: -100 }],
    ['n', 2],
    ['top_k', 40],
    ['parallel_tool_calls', false],
  ]) {
    const out = toConverseRequest(projected({ [field]: value }));
    assert.equal(out.skip, 'bedrock_unmappable_field', field);
    assert.equal(out.offendingField, field);
  }
});

test('non-streaming requests and mid-conversation system messages skip', () => {
  assert.equal(toConverseRequest(projected({ stream: undefined })).skip, 'bedrock_stream_only');
  const out = toConverseRequest(
    projected({
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'system', content: 'now be rude' },
      ],
    }),
  );
  assert.equal(out.skip, 'bedrock_unmappable_field');
  assert.equal(out.offendingField, 'messages.system');
});

test('unparsable tool_call arguments skip rather than sending a mangled input', () => {
  const out = toConverseRequest(
    projected({
      messages: [
        {
          role: 'assistant',
          tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: '{oops' } }],
        },
      ],
    }),
  );
  assert.equal(out.skip, 'bedrock_unmappable_field');
  assert.equal(out.offendingField, 'messages.tool_calls');
});

test('every mappable field is either consumed or expressed — the set matches the adapter', () => {
  // Guard against BEDROCK_MAPPABLE_FIELDS drifting from what toConverseRequest
  // actually reads: a fully-loaded mappable payload must translate cleanly.
  const out = toConverseRequest(
    projected({
      temperature: 1,
      top_p: 0.5,
      max_tokens: 10,
      max_completion_tokens: 20,
      stop: ['a'],
      tools: [{ type: 'function', function: { name: 'f', parameters: {} } }],
      tool_choice: 'auto',
      reasoning_effort: 'low',
      user: 'ppq-hash',
    }),
  );
  assert.equal(out.skip, undefined);
  assert.equal(BEDROCK_MAPPABLE_FIELDS.has('messages'), true);
});

// ---------------------------------------------------------------------------
// buildBedrockRequest
// ---------------------------------------------------------------------------

test('builds a signed ConverseStream request through the vsock tunnel mouth', () => {
  const built = buildBedrockRequest({
    candidate: CANDIDATE,
    basePayload: basePayload(),
    ports: PORTS,
    creds: CREDS,
    now: new Date('2026-08-13T12:00:00Z'),
  });

  assert.equal(built.skip, undefined);
  assert.equal(built.provider, 'bedrock');
  assert.equal(built.orSlug, 'openai/gpt-5.5');
  assert.equal(built.upstreamModel, 'us.openai.gpt-5.5-v1:0');
  assert.equal(built.apiStyle, 'bedrock');

  const { opts, bodyStr } = built;
  assert.equal(opts.host, '127.0.0.1');
  assert.equal(opts.port, 9446);
  assert.equal(opts.servername, CANDIDATE.host); // E2E TLS pin to the real host
  assert.equal(opts.path, CANDIDATE.path);
  assert.equal(opts.headers.host, CANDIDATE.host);
  assert.equal(opts.headers.accept, 'application/vnd.amazon.eventstream');
  assert.equal(opts.headers['content-length'], Buffer.byteLength(bodyStr));
  assert.match(opts.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20260813\/us-east-2\/bedrock\/aws4_request/);
  assert.equal(opts.headers['x-amz-security-token'], CREDS.sessionToken);
  assert.equal(opts.headers['x-amz-date'], '20260813T120000Z');

  // The signed body is the Converse translation: no `model`, no OpenAI keys.
  const body = JSON.parse(bodyStr);
  assert.equal(body.model, undefined);
  assert.deepEqual(body.messages, [{ role: 'user', content: [{ text: 'hello' }] }]);
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
// EventStreamToSse — through the REAL CostExtractor + rewriter
// ---------------------------------------------------------------------------

const ev = (type, payload) =>
  encodeEventStreamMessage({
    headers: { ':message-type': 'event', ':event-type': type },
    payload: Buffer.from(JSON.stringify(payload)),
  });

function fullStream() {
  return [
    ev('messageStart', { role: 'assistant' }),
    ev('contentBlockDelta', { contentBlockIndex: 0, delta: { text: 'It is ' } }),
    ev('contentBlockDelta', { contentBlockIndex: 0, delta: { text: 'sunny.' } }),
    ev('contentBlockStop', { contentBlockIndex: 0 }),
    ev('contentBlockStart', {
      contentBlockIndex: 1,
      start: { toolUse: { toolUseId: 'tool-1', name: 'get_weather' } },
    }),
    ev('contentBlockDelta', { contentBlockIndex: 1, delta: { toolUse: { input: '{"city":' } } }),
    ev('contentBlockDelta', { contentBlockIndex: 1, delta: { toolUse: { input: '"Lisbon"}' } } }),
    ev('messageStop', { stopReason: 'tool_use' }),
    ev('metadata', {
      usage: {
        inputTokens: 12,
        outputTokens: 34,
        totalTokens: 7953,
        cacheReadInputTokens: 7907,
        cacheWriteInputTokens: 5,
      },
      metrics: { latencyMs: 900 },
    }),
  ];
}

test('translates a full ConverseStream into OpenAI SSE the existing pipeline understands', () => {
  const translator = new EventStreamToSse({ upstreamModel: 'us.openai.gpt-5.5-v1:0' });
  const extractor = new CostExtractor({ isFreeModel: false });
  const rewriter = directResponseRewriter('us.openai.gpt-5.5-v1:0', 'openai/gpt-5.5');

  // Feed with ugly fragmentation: concatenate all frames, then 5-byte strides.
  const wire = Buffer.concat(fullStream());
  let client = '';
  for (let i = 0; i < wire.length; i += 5) {
    const sse = translator.feed(wire.subarray(i, i + 5));
    if (sse.length === 0) continue;
    extractor.feed(sse);
    client += rewriter.feed(sse).toString('utf8');
  }
  const tail = translator.finish();
  if (tail.length > 0) {
    extractor.feed(tail);
    client += rewriter.feed(tail).toString('utf8');
  }
  client += rewriter.finish().toString('utf8');

  // The extractor (billing input) saw the WIRE model id + additive usage.
  const usage = extractor.finish();
  assert.equal(usage.model, 'us.openai.gpt-5.5-v1:0');
  assert.equal(usage.inputTokens, 12); // EXCLUDES cache reads — hp folds them
  assert.equal(usage.outputTokens, 34);
  assert.equal(usage.cacheReadTokens, 7907);
  assert.equal(usage.cacheWriteTokens, 5);
  assert.equal(usage.totalCost, 0); // priced from the catalog, never the stream

  // The CLIENT never saw the wire id, and got well-formed OpenAI chunks.
  assert.ok(!client.includes('us.openai.gpt-5.5-v1:0'));
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

  const toolStart = parsed.find((c) => c.choices?.[0]?.delta?.tool_calls?.[0]?.id === 'tool-1');
  assert.equal(toolStart.choices[0].delta.tool_calls[0].function.name, 'get_weather');
  const argChunks = parsed
    .flatMap((c) => c.choices ?? [])
    .flatMap((c) => c.delta?.tool_calls ?? [])
    .map((t) => t.function?.arguments ?? '')
    .join('');
  assert.equal(argChunks, '{"city":"Lisbon"}');

  const finish = parsed.find((c) => c.choices?.[0]?.finish_reason);
  assert.equal(finish.choices[0].finish_reason, 'tool_calls');
});

test('stop-reason map: max_tokens → length, guardrail → content_filter, end_turn → stop', () => {
  for (const [bedrock, openai] of [
    ['end_turn', 'stop'],
    ['stop_sequence', 'stop'],
    ['max_tokens', 'length'],
    ['guardrail_intervened', 'content_filter'],
    ['made_up_future_reason', 'stop'],
  ]) {
    const translator = new EventStreamToSse({ upstreamModel: 'm' });
    const sse = translator.feed(ev('messageStop', { stopReason: bedrock })).toString('utf8');
    assert.match(sse, new RegExp(`"finish_reason":"${openai}"`), bedrock);
  }
});

test('exception events become a terminal OpenRouter-style error frame', () => {
  const translator = new EventStreamToSse({ upstreamModel: 'm' });
  const frame = encodeEventStreamMessage({
    headers: { ':message-type': 'exception', ':exception-type': 'throttlingException' },
    payload: Buffer.from(JSON.stringify({ message: 'Too many requests' })),
  });
  const sse = translator.feed(frame).toString('utf8');
  assert.match(sse, /"error"/);
  assert.match(sse, /throttlingException/);
  assert.match(sse, /Too many requests/);
  // After a fatal frame the transform goes silent — no [DONE], no more chunks.
  assert.equal(translator.feed(ev('contentBlockDelta', { delta: { text: 'x' } })).length, 0);
  assert.equal(translator.finish().length, 0);
});

test('a stream truncated mid-frame surfaces an error, not a fake completion', () => {
  const translator = new EventStreamToSse({ upstreamModel: 'm' });
  const frame = ev('contentBlockDelta', { delta: { text: 'partial answer' } });
  translator.feed(frame.subarray(0, frame.length - 2));
  const tail = translator.finish().toString('utf8');
  assert.match(tail, /"error"/);
  assert.match(tail, /ended unexpectedly/);
  assert.ok(!tail.includes('[DONE]'));
});

test('corrupted CRC mid-stream becomes an error frame, not an exception', () => {
  const translator = new EventStreamToSse({ upstreamModel: 'm' });
  const frame = ev('contentBlockDelta', { delta: { text: 'hi' } });
  frame[frame.length - 6] ^= 0xff;
  const sse = translator.feed(frame).toString('utf8');
  assert.match(sse, /"error"/);
  assert.match(sse, /corrupted/);
});
