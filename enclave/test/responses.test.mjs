// The pure parts of the in-enclave /v1/responses route (#280): what the relay
// reads off a body, what hp is told about its size, what the settle is built
// from, the identity field, and the error shape a Responses client can parse.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RESPONSES_DIALECT,
  RESPONSES_ENDPOINT,
  ResponsesOutputCounter,
  ResponsesUsageExtractor,
  applyResponsesCap,
  applyResponsesSafetyIdentifier,
  measureResponsesInput,
  openaiErrorBody,
  responsesHasWebSearch,
  responsesStreamErrorFrame,
  responsesUsage,
  toChatShapeForMeasure,
  validateResponsesRequest,
} from '../src/responses.mjs';

const ok = (body) => validateResponsesRequest(body);
const minimal = { model: 'openai/gpt-5.5', input: 'Say OK.' };

test('validate: a string input, an item list, and only the relay’s fields are read', () => {
  const r = ok({ ...minimal, temperature: 0.1, previous_response_id: 'resp_1', store: false, stream: true, max_output_tokens: 50 });
  assert.equal(r.kind, 'ok');
  assert.deepEqual(r.value, { model: 'openai/gpt-5.5', max_output_tokens: 50, stream: true });
  assert.deepEqual(ok(minimal).value, { model: 'openai/gpt-5.5', max_output_tokens: undefined, stream: false });
  assert.equal(ok({ model: 'm', input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'hi' }] }] }).kind, 'ok');
});

test('validate: the fields the relay relies on are each required in their shape', () => {
  const field = (body) => { const r = ok(body); assert.equal(r.kind, 'invalid'); return r.error.field; };
  assert.equal(field(null), 'body');
  assert.equal(field({ ...minimal, model: ' ' }), 'model');
  assert.equal(field({ model: 'm' }), 'input');
  assert.equal(field({ model: 'm', input: 5 }), 'input');
  assert.equal(field({ model: 'm', input: [{ type: 'message', role: 'user', content: 'a' }, 5] }), 'input.1', 'items are objects, as the API defines them');
  assert.equal(field({ ...minimal, instructions: 7 }), 'instructions');
  assert.equal(field({ ...minimal, max_output_tokens: 0 }), 'max_output_tokens');
  assert.equal(field({ ...minimal, stream: 'yes' }), 'stream');
});

test('measure: instructions, items and parts project onto the shape the chat measure counts', () => {
  const shape = toChatShapeForMeasure({
    instructions: 'be brief',
    input: [
      { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'what is this' }, { type: 'input_image', image_url: 'data:image/png;base64,' + 'A'.repeat(4000) }] },
      { type: 'function_call', call_id: 'c1', name: 'lookup', arguments: '{"q":"x"}' },
      { type: 'function_call_output', call_id: 'c1', output: 'found it' },
      { type: 'message', role: 'user', content: [{ type: 'input_file', filename: 'a.pdf', file_data: 'QUJDRA==' }] },
      { role: 'user', content: 'plain message item' },
    ],
    tools: [{ type: 'function', name: 'lookup', parameters: { type: 'object' } }],
  });
  assert.equal(shape.messages[0].role, 'system');
  assert.deepEqual(shape.messages[1].content[1], { type: 'image' }, 'the image carries no bytes into the text count');
  assert.match(shape.messages[2].content, /lookup/);
  assert.equal(shape.messages[3].role, 'tool');
  assert.equal(shape.messages[4].content[0].file.file_data, 'QUJDRA==');
  assert.equal(shape.messages[5].content, 'plain message item', 'an item without a type is a message');
  assert.equal(shape.tools.length, 1);
});

test('measure: the fields hp bounds spend with, over the Responses body', async () => {
  const m = await measureResponsesInput({
    instructions: 'be brief',
    input: [
      { type: 'message', role: 'user', content: 'Explain the enclave in one sentence.' },
      { type: 'message', role: 'user', content: [{ type: 'input_image', image_url: 'data:image/png;base64,' + 'A'.repeat(4000) }] },
      { type: 'message', role: 'user', content: [{ type: 'input_file', file_data: 'QUJDRA==' }] },
    ],
  });
  assert.equal(m.endpoint, RESPONSES_ENDPOINT);
  assert.equal(m.message_count, 3);
  assert.equal(m.image_parts, 1);
  assert.equal(m.file_bytes, 4);
  assert.ok(Number.isInteger(m.input_tokens_o200k) && m.input_tokens_o200k > 10 && m.input_tokens_o200k < 200, `tokenized: ${m.input_tokens_o200k}`);
  assert.equal((await measureResponsesInput({ input: 'hi' })).message_count, 1);
  assert.equal((await measureResponsesInput({ input: null })).message_count, 0, 'never throws');
});

test('cap: max_output_tokens is set when absent and clamped when present', () => {
  const a = { model: 'm', input: 'x' }; applyResponsesCap(a, 50); assert.equal(a.max_output_tokens, 50);
  const b = { model: 'm', input: 'x', max_output_tokens: 4000 }; applyResponsesCap(b, 50); assert.equal(b.max_output_tokens, 50);
  const c = { model: 'm', input: 'x', max_output_tokens: 20 }; applyResponsesCap(c, 50); assert.equal(c.max_output_tokens, 20);
});

test('identity: safety_identifier = HMAC(credit) for openai/* only; the caller’s user is dropped', () => {
  const body = { model: 'openai/gpt-5.5', input: 'x', user: 'caller-chosen' };
  applyResponsesSafetyIdentifier(body, 'credit-1', 'secret');
  assert.match(body.safety_identifier, /^[0-9a-f]{64}$/);
  assert.equal(body.user, undefined);
  const other = { model: 'anthropic/claude-sonnet-4.6', input: 'x', user: 'caller-chosen' };
  applyResponsesSafetyIdentifier(other, 'credit-1', 'secret');
  assert.deepEqual(other, { model: 'anthropic/claude-sonnet-4.6', input: 'x', user: 'caller-chosen' });
  const oss = { model: 'openai/gpt-oss-120b', input: 'x' };
  applyResponsesSafetyIdentifier(oss, 'credit-1', 'secret');
  assert.equal(oss.safety_identifier, undefined);
  const noSecret = { model: 'openai/gpt-5.5', input: 'x' };
  applyResponsesSafetyIdentifier(noSecret, 'credit-1', '');
  assert.equal(noSecret.safety_identifier, undefined);
});

test('usage (non-streaming): the response object, cached and reasoning tokens kept, incomplete reason as stop', () => {
  const u = responsesUsage({
    id: 'gen-1790000000-r1', object: 'response', model: 'openai/gpt-5.5', status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' },
    usage: { input_tokens: 120, output_tokens: 50, total_tokens: 170, input_tokens_details: { cached_tokens: 100 }, output_tokens_details: { reasoning_tokens: 30 }, cost: 0.0012 },
  });
  assert.deepEqual(u, { inputTokens: 120, outputTokens: 50, cacheReadTokens: 100, reasoningTokens: 30, totalCost: 0.0012, costReported: true, generationId: 'gen-1790000000-r1', servedModel: 'openai/gpt-5.5', stopReason: 'max_output_tokens' });
  assert.equal(responsesUsage({ id: 'resp_123', status: 'completed', usage: { input_tokens: 1 } }).generationId, '');
  assert.equal(responsesUsage(null).costReported, false);
});

const sse = (ev) => `data: ${JSON.stringify(ev)}\n`;

test('usage (streamed): created carries model + id, completed carries the usage; nothing after is read', () => {
  const x = new ResponsesUsageExtractor();
  for (const l of [
    'event: response.created',
    sse({ type: 'response.created', response: { id: 'gen-1790000000-r2', model: 'openai/gpt-5.5', status: 'in_progress', usage: null } }),
    sse({ type: 'response.output_item.added', output_index: 0, item: { type: 'message', role: 'assistant', content: [] } }),
    sse({ type: 'response.output_text.delta', delta: 'OK' }),
    sse({ type: 'response.completed', response: { id: 'gen-1790000000-r2', model: 'openai/gpt-5.5', status: 'completed', usage: { input_tokens: 14, output_tokens: 4, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 }, cost: 0.00021 } } }),
    sse({ type: 'response.failed', response: { error: { message: 'ignored after completed' } } }),
  ]) x.feed(l);
  assert.equal(x.completed, true);
  assert.equal(x.terminal, 'completed');
  assert.deepEqual(x.result, { inputTokens: 14, outputTokens: 4, cacheReadTokens: 0, reasoningTokens: 0, totalCost: 0.00021, costReported: true, generationId: 'gen-1790000000-r2', servedModel: 'openai/gpt-5.5', stopReason: 'completed' });
});

test('usage (streamed): incomplete terminates with its reason; failed and a bare error event are failures; a cut stream is neither', () => {
  const inc = new ResponsesUsageExtractor();
  inc.feed(sse({ type: 'response.incomplete', response: { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, usage: { input_tokens: 3, output_tokens: 50 } } }));
  assert.equal(inc.completed, true); assert.equal(inc.terminal, 'incomplete'); assert.equal(inc.result.stopReason, 'max_output_tokens');
  assert.equal(RESPONSES_DIALECT.capHit(inc), true);
  const failed = new ResponsesUsageExtractor();
  failed.feed(sse({ type: 'response.failed', response: { status: 'failed', error: { code: 'server_error', message: 'boom' } } }));
  assert.equal(failed.terminal, 'error'); assert.equal(failed.completed, false); assert.equal(failed.errorMessage, 'boom');
  const bare = new ResponsesUsageExtractor();
  bare.feed(sse({ type: 'error', code: 'upstream_error', message: 'died' }));
  assert.equal(bare.terminal, 'error'); assert.equal(bare.errorMessage, 'died');
  const cut = new ResponsesUsageExtractor();
  cut.feed(sse({ type: 'response.created', response: { id: 'gen-x', model: 'm' } }));
  cut.feed('data: not json');
  assert.equal(cut.terminal, null); assert.equal(cut.completed, false); assert.equal(cut.result.servedModel, 'm');
});

test('usage (streamed): BYOK bills the upstream inference cost', () => {
  const x = new ResponsesUsageExtractor();
  x.feed(sse({ type: 'response.completed', response: { status: 'completed', usage: { input_tokens: 3, output_tokens: 2, is_byok: true, cost: 0, cost_details: { upstream_inference_cost: 0.5 } } } }));
  assert.equal(x.result.totalCost, 0.5); assert.equal(x.result.isByok, true);
});

test('delta counter: output text, function arguments and reasoning text are what went out', async () => {
  const c = new ResponsesOutputCounter();
  c.feed(sse({ type: 'response.output_text.delta', delta: 'Hello there, ' }));
  c.feed(sse({ type: 'response.function_call_arguments.delta', delta: '{"q":' }));
  c.feed(sse({ type: 'response.reasoning_summary_text.delta', delta: 'thinking ' }));
  c.feed(sse({ type: 'response.output_item.added', item: { type: 'message' } }));
  c.feed(sse({ type: 'response.output_text.done', text: 'Hello there, world' }));
  const r = await c.finish();
  assert.equal(r.chars, 'Hello there, {"q":thinking '.length);
  assert.ok(r.tokens >= 5 && r.tokens <= 12, `tokens ${r.tokens}`);
});

test('error shape: OpenAI’s, typed by status; the stream frame is a named error event with a typed payload', () => {
  assert.deepEqual(openaiErrorBody(401, 'Missing credentials'), { error: { message: 'Missing credentials', type: 'authentication_error', code: 401 } });
  assert.equal(openaiErrorBody(400, 'x').error.type, 'invalid_request_error');
  assert.equal(openaiErrorBody(402, 'x').error.type, 'permission_error');
  assert.equal(openaiErrorBody(429, 'x').error.type, 'rate_limit_error');
  assert.equal(openaiErrorBody(502, 'x').error.type, 'server_error');
  assert.equal(responsesStreamErrorFrame(), 'event: error\ndata: {"type":"error","code":"upstream_error","message":"upstream error"}\n\n');
});

test('web search: a web_search or web_search_preview tool is online', () => {
  assert.equal(responsesHasWebSearch({ tools: [{ type: 'web_search_preview' }] }), true);
  assert.equal(responsesHasWebSearch({ tools: [{ type: 'function', name: 'f' }] }), false);
  assert.equal(responsesHasWebSearch({}), false);
});

test('the dialect object names every hook the relay calls', () => {
  for (const k of ['name', 'path', 'endpoint', 'upstreamPath', 'costSource', 'maxRequestBodyBytes', 'maxResponseBytes', 'forwardHeaders', 'validate', 'measure', 'requestedMaxTokens', 'applyCap', 'applyIdentity', 'UsageExtractor', 'OutputCounter', 'usageOf', 'errorBody', 'streamErrorFrame', 'capHit', 'hasWebSearch', 'usageMissingCode']) {
    assert.ok(k in RESPONSES_DIALECT, k);
  }
  assert.equal(RESPONSES_DIALECT.usageMissingCode, 'responses_usage_missing');
});
