// #480: Anthropic Messages ⇄ chat-completions translation for a Venice
// candidate on the /v1/messages relay.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  messagesToChatRequest,
  ChatToMessagesSse,
  ChatJsonToMessages,
  chatJsonToMessage,
  anthropicUsageFromChat,
  REASONING_PING_MS,
} from '../src/chatMessages.mjs';
import { buildVeniceChatBody } from '../src/upstreams.mjs';

const VENICE = {
  provider: 'venice', api_style: 'openai', host: 'api.venice.ai', path: '/api/v1/chat/completions',
  key_ref: 'venice', upstream_model: 'zai-glm-5.3-flash-uncensored', or_slug: 'venice/glm-5-3-flash-uncensored',
  supports_tools: true, supports_image_input: true, zdr: true,
};

const events = (text) => text.split('\n\n').filter(Boolean).map((block) => {
  const lines = block.split('\n');
  return {
    event: lines.find((l) => l.startsWith('event:'))?.slice(6).trim(),
    data: JSON.parse(lines.find((l) => l.startsWith('data:')).slice(5).trim()),
  };
});
const sse = (obj) => `data: ${typeof obj === 'string' ? obj : JSON.stringify(obj)}\n\n`;
const run = (t, frames) => {
  let out = '';
  for (const f of frames) out += t.feed(Buffer.from(f)).toString('utf8');
  return out + t.finish().toString('utf8');
};

test('request: a Claude Code turn maps onto the chat wire, tool results first', () => {
  const { payload, skip } = messagesToChatRequest({
    model: 'zai-glm-5.3-flash-uncensored',
    max_tokens: 100,
    stream: true,
    temperature: 0.5,
    system: [{ type: 'text', text: 'You are Claude Code.' }, { type: 'text', text: 'Be brief.', cache_control: { type: 'ephemeral' } }],
    metadata: { user_id: 'x' },
    thinking: { type: 'enabled', budget_tokens: 2048 },
    output_config: { effort: 'high' },
    context_management: { edits: [] },
    tools: [{ name: 'Bash', description: 'Run', input_schema: { type: 'object', properties: { command: { type: 'string' } } }, cache_control: { type: 'ephemeral' } }],
    tool_choice: { type: 'auto', disable_parallel_tool_use: true },
    messages: [
      { role: 'user', content: 'list files' },
      { role: 'assistant', content: [
        { type: 'thinking', thinking: 'hmm', signature: 'sig' },
        { type: 'text', text: 'Running it.' },
        { type: 'tool_use', id: 'call_1', name: 'Bash', input: { command: 'ls' } },
      ] },
      { role: 'user', content: [
        { type: 'text', text: '<system-reminder>x</system-reminder>' },
        { type: 'tool_result', tool_use_id: 'call_1', content: [{ type: 'text', text: 'a.txt' }] },
      ] },
      { role: 'assistant', content: [{ type: 'tool_use', id: 'call_2', name: 'Bash', input: { command: 'false' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'call_2', content: 'exit 1', is_error: true }] },
    ],
  });
  assert.equal(skip, undefined);
  assert.deepEqual(payload.messages, [
    { role: 'system', content: 'You are Claude Code.\n\nBe brief.' },
    { role: 'user', content: 'list files' },
    { role: 'assistant', content: 'Running it.', tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'Bash', arguments: '{"command":"ls"}' } }] },
    { role: 'tool', tool_call_id: 'call_1', content: 'a.txt' },
    { role: 'user', content: '<system-reminder>x</system-reminder>' },
    { role: 'assistant', content: null, tool_calls: [{ id: 'call_2', type: 'function', function: { name: 'Bash', arguments: '{"command":"false"}' } }] },
    { role: 'tool', tool_call_id: 'call_2', content: 'Error: exit 1' },
  ]);
  assert.deepEqual(payload.tools, [{ type: 'function', function: { name: 'Bash', description: 'Run', parameters: { type: 'object', properties: { command: { type: 'string' } } } } }]);
  assert.equal(payload.tool_choice, 'auto');
  assert.equal(payload.parallel_tool_calls, false);
  assert.equal(payload.max_tokens, 100);
  assert.equal(payload.temperature, 0.5);
  assert.equal(payload.stream, true);
  for (const k of ['metadata', 'thinking', 'output_config', 'context_management', 'system']) assert.equal(k in payload, false, k);
});

test('request: images become data-URI parts; tool_choice and stop map', () => {
  const { payload } = messagesToChatRequest({
    model: 'm', max_tokens: 10, stop_sequences: ['END'],
    tools: [{ name: 'T', input_schema: { type: 'object' } }],
    tool_choice: { type: 'tool', name: 'T' },
    messages: [{ role: 'user', content: [
      { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } },
      { type: 'text', text: 'what is this' },
    ] }],
  });
  assert.deepEqual(payload.messages[0].content, [
    { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } },
    { type: 'text', text: 'what is this' },
  ]);
  assert.deepEqual(payload.stop, ['END']);
  assert.deepEqual(payload.tool_choice, { type: 'function', function: { name: 'T' } });
  assert.equal(messagesToChatRequest({ model: 'm', max_tokens: 1, tool_choice: { type: 'any' }, tools: [{ name: 'T' }], messages: [{ role: 'user', content: 'x' }] }).payload.tool_choice, 'required');
});

test('request (#493): a system entry inside messages[] becomes a chat system message in place', () => {
  const env = [{ type: 'text', text: '# Environment' }, { type: 'text', text: '' }, { type: 'text', text: 'cwd: /work', cache_control: { type: 'ephemeral' } }];
  const { payload, skip } = messagesToChatRequest({
    model: 'm',
    max_tokens: 10,
    system: 'You are Claude Code.',
    messages: [
      { role: 'user', content: 'read note.txt' },
      { role: 'system', content: env },
      { role: 'assistant', content: [{ type: 'tool_use', id: 'call_1', name: 'Read', input: { path: 'note.txt' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'call_1', content: 'pineapple' }] },
      { role: 'system', content: 'string form' },
      { role: 'system', content: '' },
    ],
  });
  assert.equal(skip, undefined);
  assert.deepEqual(payload.messages, [
    { role: 'system', content: 'You are Claude Code.' },
    { role: 'user', content: 'read note.txt' },
    { role: 'system', content: '# Environment\n\ncwd: /work' },
    { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'Read', arguments: '{"path":"note.txt"}' } }] },
    { role: 'tool', tool_call_id: 'call_1', content: 'pineapple' },
    { role: 'system', content: 'string form' },
  ]);

  // The translated payload clears the chat gate and Venice shaping.
  const built = buildVeniceChatBody(payload, VENICE);
  assert.equal(built.skip, undefined);

  const base = { model: 'm', max_tokens: 10 };
  // Between a tool call and its result it also stays put (Venice takes it
  // there; probed on every tool-capable row, #493).
  assert.deepEqual(
    messagesToChatRequest({ ...base, messages: [
      { role: 'user', content: 'x' },
      { role: 'assistant', content: [{ type: 'tool_use', id: 'call_1', name: 'Read', input: {} }] },
      { role: 'system', content: 'env' },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'call_1', content: 'ok' }] },
    ] }).payload.messages.map((m) => m.role),
    ['user', 'assistant', 'system', 'tool'],
  );
  // Non-text system content, other roles and a system-only conversation still skip.
  assert.deepEqual(
    messagesToChatRequest({ ...base, messages: [{ role: 'user', content: 'x' }, { role: 'system', content: [{ type: 'image', source: {} }] }] }),
    { skip: 'unmappable_field', offendingField: 'messages.content' },
  );
  assert.deepEqual(
    messagesToChatRequest({ ...base, messages: [{ role: 'user', content: 'x' }, { role: 'developer', content: 'y' }] }),
    { skip: 'unmappable_field', offendingField: 'messages.role' },
  );
  assert.deepEqual(messagesToChatRequest({ ...base, messages: [{ role: 'system', content: 'only me' }] }), { skip: 'unmappable_field', offendingField: 'messages' });
});

test('request: what the chat wire cannot carry skips the candidate, named', () => {
  const base = { model: 'm', max_tokens: 10, messages: [{ role: 'user', content: 'x' }] };
  assert.deepEqual(messagesToChatRequest({ ...base, output_config: { format: { type: 'json_schema' } } }), { skip: 'unmappable_field', offendingField: 'output_config.format' });
  assert.deepEqual(messagesToChatRequest({ ...base, stop_sequences: ['a', 'b', 'c', 'd', 'e'] }), { skip: 'unmappable_field', offendingField: 'stop_sequences' });
  assert.deepEqual(messagesToChatRequest({ ...base, tools: [{ type: 'bash_20250124', name: 'bash' }] }), { skip: 'unmappable_field', offendingField: 'tools.type' });
  assert.deepEqual(messagesToChatRequest({ ...base, mystery: 1 }), { skip: 'unmappable_field', offendingField: 'mystery' });
  assert.deepEqual(messagesToChatRequest({ ...base, messages: [{ role: 'assistant', content: 'only me' }] }), { skip: 'unmappable_field', offendingField: 'messages' });
  assert.deepEqual(
    messagesToChatRequest({ ...base, messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] }),
    { skip: 'unmappable_field', offendingField: 'messages.content' },
  );
});

test('request: the caller’s nested objects are never mutated', () => {
  const tool = { name: 'T', input_schema: { type: 'object' } };
  const msg = { role: 'user', content: [{ type: 'text', text: 'x' }] };
  const before = JSON.stringify([tool, msg]);
  messagesToChatRequest({ model: 'm', max_tokens: 5, tools: [tool], messages: [msg] });
  assert.equal(JSON.stringify([tool, msg]), before);
});

test('Venice shaping: the chat gate, projection and Venice parameters run on the translated payload', () => {
  const { payload } = messagesToChatRequest({ model: VENICE.upstream_model, max_tokens: 50, stream: true, messages: [{ role: 'user', content: 'hi' }] });
  const { body, skip } = buildVeniceChatBody(payload, VENICE);
  assert.equal(skip, undefined);
  assert.equal(body.model, VENICE.upstream_model);
  assert.deepEqual(body.stream_options, { include_usage: true }, 'usage is pinned on a stream');
  assert.deepEqual(body.venice_parameters, { include_venice_system_prompt: false }, 'Venice’s own system prompt stays off');

  // A tool request on a row without tool support is the chat gate's bail.
  const tooled = messagesToChatRequest({ model: VENICE.upstream_model, max_tokens: 5, tools: [{ name: 'T' }], messages: [{ role: 'user', content: 'x' }] }).payload;
  assert.equal(buildVeniceChatBody(tooled, { ...VENICE, supports_tools: false }).skip, 'tools_unsupported_by_model');
  // More images than the row takes per message: Venice's own limit.
  const img = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } };
  const twoImages = messagesToChatRequest({ model: VENICE.upstream_model, max_tokens: 5, messages: [{ role: 'user', content: [img, img, { type: 'text', text: 'x' }] }] }).payload;
  assert.equal(buildVeniceChatBody(twoImages, VENICE).skip, 'too_many_images');
  // Not a Venice candidate: never shaped as one.
  assert.equal(buildVeniceChatBody(payload, { ...VENICE, provider: 'fireworks', host: 'api.fireworks.ai' }).skip, 'endpoint_not_served_direct');
});

test('stream: text then a tool call, usage on the last chunk, in Anthropic’s additive convention', () => {
  const t = new ChatToMessagesSse({ upstreamModel: 'up' });
  const base = { id: 'c1', object: 'chat.completion.chunk', model: 'up-wire' };
  const out = run(t, [
    sse({ ...base, choices: [{ index: 0, delta: { role: 'assistant', content: '' } }] }),
    sse({ ...base, choices: [{ index: 0, delta: { content: 'Run' } }] }),
    sse({ ...base, choices: [{ index: 0, delta: { content: 'ning.' } }] }),
    sse({ ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'call_9', type: 'function', function: { name: 'Bash', arguments: '' } }] } }] }),
    sse({ ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"command":' } }] } }] }),
    sse({ ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '"ls"}' } }] } }] }),
    sse({ ...base, choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] }),
    sse({ ...base, choices: [], usage: { prompt_tokens: 100, completion_tokens: 7, prompt_tokens_details: { cached_tokens: 60 } } }),
    sse('[DONE]'),
  ]);
  const ev = events(out);
  assert.deepEqual(ev.map((e) => e.event), [
    'message_start', 'content_block_start', 'content_block_delta', 'content_block_delta', 'content_block_stop',
    'content_block_start', 'content_block_delta', 'content_block_delta', 'content_block_stop',
    'message_delta', 'message_stop',
  ]);
  assert.equal(ev[0].data.message.model, 'up-wire', 'the wire echo, for hp’s served-model tripwire');
  assert.equal(t.wireModel, 'up-wire');
  assert.deepEqual(ev[5].data.content_block, { type: 'tool_use', id: 'call_9', name: 'Bash', input: {} });
  assert.equal(ev[6].data.delta.partial_json + ev[7].data.delta.partial_json, '{"command":"ls"}');
  assert.equal(ev[9].data.delta.stop_reason, 'tool_use');
  assert.deepEqual(ev[9].data.usage, { input_tokens: 40, output_tokens: 7, cache_read_input_tokens: 60, cache_creation_input_tokens: 0 });
});

test('stream: a tool name that arrives after the id is held; two sequential calls get two blocks; a no-arg call parses as {}', () => {
  const t = new ChatToMessagesSse({ upstreamModel: 'up' });
  const c = (delta, extra = {}) => sse({ model: 'up', choices: [{ index: 0, delta, ...extra }] });
  const out = run(t, [
    c({ tool_calls: [{ index: 0, id: 'a', function: { arguments: '' } }] }),
    c({ tool_calls: [{ index: 0, function: { name: 'Read', arguments: '{"p":1}' } }] }),
    c({ tool_calls: [{ index: 1, id: 'b', function: { name: 'Now', arguments: '' } }] }),
    c({}, { finish_reason: 'tool_calls' }),
    sse('[DONE]'),
  ]);
  const ev = events(out);
  const starts = ev.filter((e) => e.event === 'content_block_start').map((e) => e.data.content_block);
  assert.deepEqual(starts, [
    { type: 'tool_use', id: 'a', name: 'Read', input: {} },
    { type: 'tool_use', id: 'b', name: 'Now', input: {} },
  ]);
  const deltas = ev.filter((e) => e.event === 'content_block_delta').map((e) => [e.data.index, e.data.delta.partial_json]);
  assert.deepEqual(deltas, [[0, '{"p":1}'], [1, '{}']]);
  assert.equal(ev.at(-1).event, 'message_stop');
});

test('stream: interleaved tool fragments end as an error, never silently dropped', () => {
  const t = new ChatToMessagesSse({ upstreamModel: 'up' });
  const c = (delta) => sse({ model: 'up', choices: [{ index: 0, delta }] });
  const out = run(t, [
    c({ tool_calls: [{ index: 0, id: 'a', function: { name: 'A', arguments: '{"x":' } }] }),
    c({ tool_calls: [{ index: 1, id: 'b', function: { name: 'B', arguments: '{}' } }] }),
    c({ tool_calls: [{ index: 0, function: { arguments: '1}' } }] }),
  ]);
  const ev = events(out);
  assert.equal(ev.at(-1).event, 'error');
  assert.match(ev.at(-1).data.error.message, /interleaved/);
});

test('stream: end without [DONE] after a finish_reason is complete; before one it is an error', () => {
  const ok = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [
    sse({ model: 'up', choices: [{ index: 0, delta: { content: 'hi' }, finish_reason: 'length' }], usage: { prompt_tokens: 3, completion_tokens: 1 } }),
  ]));
  assert.equal(ok.at(-1).event, 'message_stop');
  assert.equal(ok.at(-2).data.delta.stop_reason, 'max_tokens');
  assert.deepEqual(ok.at(-2).data.usage, { input_tokens: 3, output_tokens: 1, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 });

  const cut = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [sse({ model: 'up', choices: [{ index: 0, delta: { content: 'hi' } }] })]));
  assert.equal(cut.at(-1).event, 'error');
  assert.match(cut.at(-1).data.error.message, /ended unexpectedly/);
});

test('stream: an upstream error chunk or a non-JSON frame is a terminal error event', () => {
  const err = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [
    sse({ model: 'up', choices: [{ index: 0, delta: { content: 'a' } }] }),
    sse({ error: { message: 'Model overloaded', code: 503 } }),
    sse({ model: 'up', choices: [{ index: 0, delta: { content: 'never' } }] }),
  ]));
  assert.deepEqual(err.map((e) => e.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'error']);
  assert.match(err.at(-1).data.error.message, /Model overloaded/);
  const bad = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), ['data: {nope\n\n']));
  assert.equal(bad.at(-1).event, 'error');
});

test('stream: frames split mid-line reassemble; reasoning is not relayed but keeps the line alive with ping', () => {
  let clock = 0;
  const t = new ChatToMessagesSse({ upstreamModel: 'up', now: () => clock });
  const frame = sse({ model: 'up', choices: [{ index: 0, delta: { content: 'héllo' } }] });
  const bytes = Buffer.from(frame);
  let out = t.feed(bytes.subarray(0, 17)).toString() + t.feed(bytes.subarray(17)).toString();
  assert.match(out, /héllo/);
  clock += REASONING_PING_MS + 1;
  const ping = t.feed(Buffer.from(sse({ model: 'up', choices: [{ index: 0, delta: { reasoning_content: 'thinking…' } }] }))).toString();
  assert.equal(events(ping)[0].event, 'ping');
  assert.doesNotMatch(ping, /thinking/);
  const quiet = t.feed(Buffer.from(sse({ model: 'up', choices: [{ index: 0, delta: { reasoning_content: 'more' } }] }))).toString();
  assert.equal(quiet, '', 'no second ping inside the interval');
});

test('usage: chat cache buckets are subsets of prompt_tokens; clamped, never negative', () => {
  assert.deepEqual(anthropicUsageFromChat({ prompt_tokens: 626, completion_tokens: 34, prompt_tokens_details: { cached_tokens: 544 }, cache_read_input_tokens: 544 }),
    { input_tokens: 82, output_tokens: 34, cache_read_input_tokens: 544, cache_creation_input_tokens: 0 });
  assert.deepEqual(anthropicUsageFromChat({ prompt_tokens: 10, completion_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 3 }),
    { input_tokens: 3, output_tokens: 1, cache_read_input_tokens: 4, cache_creation_input_tokens: 3 });
  assert.equal(anthropicUsageFromChat({ prompt_tokens: 1, prompt_tokens_details: { cached_tokens: 9 } }).input_tokens, 0);
  assert.deepEqual(anthropicUsageFromChat(undefined), { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 });
});

test('json: one chat.completion → one Message; an error body → Anthropic’s error object, flagged failed', () => {
  const msg = chatJsonToMessage({
    model: 'up-wire',
    choices: [{ index: 0, finish_reason: 'tool_calls', message: { role: 'assistant', content: 'ok', tool_calls: [
      { id: 'c1', type: 'function', function: { name: 'Bash', arguments: '{"command":"ls"}' } },
      { id: 'c2', type: 'function', function: { name: 'Bash', arguments: 'not json' } },
    ] } }],
    usage: { prompt_tokens: 20, completion_tokens: 5, prompt_tokens_details: { cached_tokens: 8 } },
  }, { upstreamModel: 'up' });
  assert.equal(msg.model, 'up-wire');
  assert.deepEqual(msg.content, [
    { type: 'text', text: 'ok' },
    { type: 'tool_use', id: 'c1', name: 'Bash', input: { command: 'ls' } },
    { type: 'tool_use', id: 'c2', name: 'Bash', input: {} },
  ]);
  assert.equal(msg.stop_reason, 'tool_use');
  assert.deepEqual(msg.usage, { input_tokens: 12, output_tokens: 5, cache_read_input_tokens: 8, cache_creation_input_tokens: 0 });

  const t = new ChatJsonToMessages({ upstreamModel: 'up' });
  t.feed(Buffer.from(JSON.stringify({ error: { message: 'bad thing' } })));
  const out = JSON.parse(t.finish().toString());
  assert.equal(out.type, 'error');
  assert.match(out.error.message, /bad thing/);
  assert.equal(t.failed, true);

  const garbage = new ChatJsonToMessages({ upstreamModel: 'up' });
  garbage.feed(Buffer.from('<html>'));
  assert.equal(JSON.parse(garbage.finish().toString()).type, 'error');
  assert.equal(garbage.failed, true);
});

test('stream (Codex review): [DONE] before any finish_reason is a cut stream, not a clean end', () => {
  const ev = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [
    sse({ model: 'up', choices: [{ index: 0, delta: { content: 'half an ans' } }] }),
    sse('[DONE]'),
  ]));
  assert.equal(ev.at(-1).event, 'error');
  assert.equal(ev.some((e) => e.event === 'message_stop'), false);
});

test('stream (Codex review): a tool name split across chunks reaches the client whole', () => {
  const c = (delta, extra = {}) => sse({ model: 'up', choices: [{ index: 0, delta, ...extra }] });
  const ev = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [
    c({ tool_calls: [{ index: 0, id: 'a', function: { name: 'Ba' } }] }),
    c({ tool_calls: [{ index: 0, function: { name: 'sh' } }] }),
    c({ tool_calls: [{ index: 0, function: { arguments: '{"command":"ls"}' } }] }),
    c({ tool_calls: [{ index: 1, id: 'b', function: { name: 'No' } }] }),
    c({ tool_calls: [{ index: 1, function: { name: 'Args' } }] }),
    c({}, { finish_reason: 'tool_calls' }),
    sse('[DONE]'),
  ]));
  const starts = ev.filter((e) => e.event === 'content_block_start').map((e) => e.data.content_block.name);
  assert.deepEqual(starts, ['Bash', 'NoArgs']);
  assert.equal(ev.at(-1).event, 'message_stop');
});

test('refusals (Codex review): refusal text is kept and the stop reason says so, on the stream and in JSON', () => {
  const ev = events(run(new ChatToMessagesSse({ upstreamModel: 'up' }), [
    sse({ model: 'up', choices: [{ index: 0, delta: { refusal: 'I can’t help with that.' } }] }),
    sse({ model: 'up', choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }),
    sse('[DONE]'),
  ]));
  assert.equal(ev.find((e) => e.event === 'content_block_delta').data.delta.text, 'I can’t help with that.');
  assert.equal(ev.find((e) => e.event === 'message_delta').data.delta.stop_reason, 'refusal');
  const msg = chatJsonToMessage({ model: 'up', choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: null, refusal: 'No.' } }] }, { upstreamModel: 'up' });
  assert.deepEqual(msg.content, [{ type: 'text', text: 'No.' }]);
  assert.equal(msg.stop_reason, 'refusal');
});
