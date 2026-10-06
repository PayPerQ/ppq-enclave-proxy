// The pure parts of the in-enclave /v1/messages route (#275): what the
// handler reads off a body, what hp is told about its size, what the settle
// is built from, and the error shape a Messages client can parse.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MESSAGES_ENDPOINT,
  MessagesUsageExtractor,
  anthropicErrorBody,
  anthropicErrorTypeFor,
  anthropicFirstPartyId,
  measureMessagesInput,
  messagesStreamErrorFrame,
  messagesUsage,
  projectCountTokensBody,
  toChatShapeForMeasure,
  validateMessagesRequest,
} from '../src/messages.mjs';

const ok = (body) => validateMessagesRequest(body);
const minimal = { model: 'anthropic/claude-sonnet-4.6', max_tokens: 64, messages: [{ role: 'user', content: 'hi' }] };

test('validate: a minimal Messages body is accepted and only the handler’s fields are read', () => {
  const r = ok({ ...minimal, metadata: { user_id: 'x' }, temperature: 0.2, stream: true });
  assert.equal(r.kind, 'ok');
  assert.deepEqual(r.value, { model: 'anthropic/claude-sonnet-4.6', max_tokens: 64, stream: true });
  assert.equal(ok(minimal).value.stream, false, 'stream defaults to false');
});

test('validate: the fields the handler relies on are each required in their shape', () => {
  const field = (body) => { const r = ok(body); assert.equal(r.kind, 'invalid'); return r.error.field; };
  assert.equal(field(null), 'body');
  assert.equal(field('[]'), 'body');
  assert.equal(field({ ...minimal, model: '' }), 'model');
  assert.equal(field({ ...minimal, max_tokens: undefined }), 'max_tokens');
  assert.equal(field({ ...minimal, max_tokens: 0 }), 'max_tokens');
  assert.equal(field({ ...minimal, max_tokens: '64' }), 'max_tokens');
  assert.equal(field({ ...minimal, messages: [] }), 'messages');
  assert.equal(field({ ...minimal, messages: [{ content: 'x' }] }), 'messages.0.role');
  assert.equal(field({ ...minimal, messages: [{ role: '', content: 'x' }] }), 'messages.0.role');
  assert.equal(field({ ...minimal, messages: [{ role: 7, content: 'x' }] }), 'messages.0.role');
  assert.equal(field({ ...minimal, messages: [{ role: 'user', content: 5 }] }), 'messages.0.content');
  assert.equal(field({ ...minimal, system: 5 }), 'system');
  assert.equal(field({ ...minimal, stream: 'yes' }), 'stream');
});

test('validate: a system-role entry inside messages passes — OpenRouter folds it in, as the horse-power route did (#282)', () => {
  const r = ok({ ...minimal, messages: [{ role: 'user', content: 'hello' }, { role: 'system', content: 'be terse' }, { role: 'user', content: 'hi' }] });
  assert.equal(r.kind, 'ok');
});

test('validate: content blocks and a system array pass', () => {
  const r = ok({
    ...minimal,
    system: [{ type: 'text', text: 'be brief' }],
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'what is this' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }] },
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'lookup', input: { q: 'x' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'found it' }] },
    ],
  });
  assert.equal(r.kind, 'ok');
});

test('measure: system, blocks, tools and media are projected the way the chat measure counts them', () => {
  const shape = toChatShapeForMeasure({
    system: 'be brief',
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'what is this' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'A'.repeat(4000) } }] },
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'lookup', input: { q: 'x' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: 'found it' }] }] },
      { role: 'user', content: [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: 'QUJDRA==' } }] },
    ],
    tools: [{ name: 'lookup', input_schema: { type: 'object' } }],
  });
  assert.equal(shape.messages[0].role, 'system');
  assert.equal(shape.messages[0].content, 'be brief');
  // The image carries no bytes into the text count; the document carries its base64 as a file part.
  assert.deepEqual(shape.messages[1].content[1], { type: 'image' });
  assert.equal(shape.messages[4].content[0].type, 'file');
  assert.equal(shape.messages[4].content[0].file.file_data, 'QUJDRA==');
  // tool_use input and tool_result content are text the model reads.
  assert.match(shape.messages[2].content[0].text, /lookup/);
  assert.match(shape.messages[3].content[0].text, /found it/);
  assert.equal(shape.tools.length, 1);
});

test('measure: the fields hp bounds spend with, over the Anthropic body', async () => {
  const m = await measureMessagesInput({
    system: 'be brief',
    messages: [
      { role: 'user', content: 'Explain the enclave in one sentence.' },
      { role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'A'.repeat(4000) } }] },
      { role: 'user', content: [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: 'QUJDRA==' } }] },
    ],
  });
  assert.equal(m.endpoint, MESSAGES_ENDPOINT);
  assert.equal(m.message_count, 3, 'the caller’s messages, not the synthetic system one');
  assert.equal(m.image_parts, 1);
  assert.equal(m.file_bytes, 4);
  assert.equal(m.audio_bytes, 0);
  assert.ok(m.input_bytes > 100);
  assert.ok(Number.isInteger(m.input_tokens_o200k) && m.input_tokens_o200k > 10, `tokenized: ${m.input_tokens_o200k}`);
  assert.ok(m.input_tokens_o200k < 200, 'the 4000-char image payload was not counted as text');
});

test('measure: never throws on a malformed body', async () => {
  const m = await measureMessagesInput({ messages: 'nope', system: { bad: true } });
  assert.equal(m.message_count, 0);
  assert.equal(m.endpoint, MESSAGES_ENDPOINT);
});

test('usage (non-streaming): OpenRouter’s Messages body, additive cache buckets kept', () => {
  const u = messagesUsage({
    id: 'gen-1790000000-abc',
    type: 'message',
    model: 'anthropic/claude-sonnet-4.6',
    stop_reason: 'end_turn',
    usage: { input_tokens: 12, output_tokens: 5, cache_read_input_tokens: 104, cache_creation_input_tokens: 0, cost: 0.00031 },
  });
  assert.deepEqual(u, {
    inputTokens: 12, outputTokens: 5, cacheReadTokens: 104, cacheWriteTokens: 0,
    totalCost: 0.00031, costReported: true, generationId: 'gen-1790000000-abc',
    servedModel: 'anthropic/claude-sonnet-4.6', stopReason: 'end_turn',
  });
  assert.equal(messagesUsage(null).costReported, false);
  assert.equal(messagesUsage({ id: 'msg_123', usage: { input_tokens: 1 } }).generationId, '', 'only gen- ids are OpenRouter generation ids');
});

const sse = (ev) => `data: ${JSON.stringify(ev)}\n`;

test('usage (streamed): message_start carries input + cache, message_delta carries output + stop + cost; later silence never zeroes earlier numbers', () => {
  const x = new MessagesUsageExtractor();
  const lines = [
    'event: message_start',
    sse({ type: 'message_start', message: { id: 'gen-1773075693-jw8S', type: 'message', role: 'assistant', content: [], model: 'anthropic/claude-sonnet-4.6', stop_reason: null, usage: { input_tokens: 2500, output_tokens: 1, cache_creation_input_tokens: 0, cache_read_input_tokens: 2000 } } }),
    sse({ type: 'ping' }),
    sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'OK' } }),
    sse({ type: 'content_block_stop', index: 0 }),
    sse({ type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 7, cost: 0.0042, cost_details: { upstream_inference_cost: null } } }),
    sse({ type: 'message_stop' }),
    'data: [DONE]',
  ];
  for (const l of lines) x.feed(l);
  assert.equal(x.completed, true);
  assert.equal(x.terminal, 'message_stop');
  assert.deepEqual(x.result, {
    inputTokens: 2500, outputTokens: 7, cacheReadTokens: 2000, cacheWriteTokens: 0,
    totalCost: 0.0042, costReported: true, generationId: 'gen-1773075693-jw8S',
    servedModel: 'anthropic/claude-sonnet-4.6', stopReason: 'end_turn',
  });
});

test('usage (streamed): a BYOK generation bills the upstream inference cost', () => {
  const x = new MessagesUsageExtractor();
  x.feed(sse({ type: 'message_start', message: { model: 'm', usage: { input_tokens: 3 } } }));
  x.feed(sse({ type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2, is_byok: true, cost: 0, cost_details: { upstream_inference_cost: 0.5 } } }));
  x.feed(sse({ type: 'message_stop' }));
  assert.equal(x.result.totalCost, 0.5);
  assert.equal(x.result.isByok, true);
});

test('usage (streamed): an error event or a stream cut before message_stop is a failed generation', () => {
  const errored = new MessagesUsageExtractor();
  errored.feed(sse({ type: 'message_start', message: { model: 'm', usage: { input_tokens: 3 } } }));
  errored.feed(sse({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }));
  errored.feed(sse({ type: 'message_stop' })); // ignored after the error
  assert.equal(errored.terminal, 'error');
  assert.equal(errored.completed, false);
  assert.equal(errored.errorMessage, 'Overloaded');

  const cut = new MessagesUsageExtractor();
  cut.feed(sse({ type: 'message_start', message: { model: 'm', usage: { input_tokens: 3 } } }));
  cut.feed('data: not json');
  cut.feed('');
  assert.equal(cut.terminal, null);
  assert.equal(cut.completed, false);
  assert.equal(cut.result.inputTokens, 3);
  assert.equal(cut.result.outputTokens, 0, 'message_start’s placeholder output count is not kept');
});

test('error shape: Anthropic’s own, with the type the status maps to', () => {
  assert.deepEqual(anthropicErrorBody('authentication_error', 'Missing credentials'), {
    type: 'error', error: { type: 'authentication_error', message: 'Missing credentials' },
  });
  assert.equal(anthropicErrorTypeFor(400), 'invalid_request_error');
  assert.equal(anthropicErrorTypeFor(401), 'authentication_error');
  assert.equal(anthropicErrorTypeFor(402), 'permission_error');
  assert.equal(anthropicErrorTypeFor(429), 'rate_limit_error');
  assert.equal(anthropicErrorTypeFor(502), 'api_error');
  const frame = messagesStreamErrorFrame();
  assert.match(frame, /^event: error\ndata: \{"type":"error","error":\{"type":"api_error","message":"upstream error"\}\}\n\n$/);
});

test('count_tokens: only the count-bearing fields are forwarded, model pinned', () => {
  const body = projectCountTokensBody(
    { model: 'claude-sonnet-4-6', messages: [{ role: 'user', content: 'hi' }], system: 's', tools: [{ name: 't' }], max_tokens: 10, metadata: { user_id: 'u' }, stream: true, thinking: { type: 'enabled', budget_tokens: 1024 } },
    'claude-sonnet-4-6-20260301',
  );
  assert.deepEqual(Object.keys(body).sort(), ['messages', 'model', 'system', 'thinking', 'tools']);
  assert.equal(body.model, 'claude-sonnet-4-6-20260301');
  assert.deepEqual(projectCountTokensBody(null, 'm'), { model: 'm' });
});

// Source pins on server.mjs's messagesRequest: the sealing-failure path drains
// the upstream through the same pump and settles through settleNow, so both
// must exist before the first `await` that can fail (CodeRabbit on #276).
test('source pin: in messagesRequest the pump and settleNow are defined before sealing can fail', async () => {
  const { readFileSync } = await import('node:fs');
  const SRC = readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8');
  const fn = SRC.slice(SRC.indexOf('async function messagesRequest('), SRC.indexOf('async function handleCountTokens('));
  // The served path's assignment (not the refused path's `const respEnc = …`).
  const sealAt = fn.search(/\n\s*respEnc = await ehbpRecipient\.responseEncryptor\(/);
  assert.ok(sealAt > 0);
  for (const decl of ['const feedLines = ', 'const decoder = new TextDecoder()', 'let jsonBody = ', 'async function drainForSettle()', 'const settleNow = ()']) {
    const at = fn.indexOf(decl);
    assert.ok(at > 0 && at < sealAt, `${decl} is declared before the sealing attempt`);
  }
  // drainForSettle has its own data listener (before); the live one comes after.
  assert.ok(fn.lastIndexOf("upRes.on('data'") > sealAt, 'the live data listener attaches after sealing succeeded');
  // Both readers are the same function, so a JSON answer is kept for its
  // usage block on the drain path as on the live one (CodeRabbit on #276).
  const drain = fn.slice(fn.indexOf('async function drainForSettle()'), fn.indexOf('const settleNow = ()'));
  assert.match(drain, /upRes\.on\('data', readUpstream\)/);
  const live = fn.slice(fn.lastIndexOf("upRes.on('data'"));
  assert.match(live.split('\n').slice(0, 3).join('\n'), /readUpstream\(raw\)/);
});

test('count_tokens: the first-party id comes from hp’s Anthropic candidate, else from the slug, else nothing', () => {
  const direct = [{ provider: 'anthropic', api_style: 'anthropic', upstream_model: 'claude-sonnet-4-6-20260301' }];
  assert.equal(anthropicFirstPartyId('anthropic/claude-sonnet-4.6', direct), 'claude-sonnet-4-6-20260301');
  // No direct row (dev; direct providers off): the undated alias from the slug.
  assert.equal(anthropicFirstPartyId('anthropic/claude-sonnet-4.6', [{ provider: 'openrouter', api_style: 'openai' }]), 'claude-sonnet-4-6');
  assert.equal(anthropicFirstPartyId('anthropic/claude-haiku-4.5:nitro', []), 'claude-haiku-4-5');
  // Anthropic's own form passes through.
  assert.equal(anthropicFirstPartyId('claude-sonnet-4-6', []), 'claude-sonnet-4-6');
  // Not a Claude model: no first-party id.
  assert.equal(anthropicFirstPartyId('openai/gpt-5.5', []), null);
  assert.equal(anthropicFirstPartyId('deepseek/deepseek-v4-flash', []), null);
  assert.equal(anthropicFirstPartyId('', []), null);
});
