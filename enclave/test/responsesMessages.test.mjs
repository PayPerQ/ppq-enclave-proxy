// The Messages ⇄ Responses translation (horse-power #1156), replaying REAL
// Responses bodies recorded 2026-09-28 (responsesMessages.fixtures.json), not
// hand-written ones. Mirror of horse-power bedrockMessagesDirect.test.ts; hp's
// enclaveMessagesTranslatorConformance test holds the two ports identical.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import {
  MESSAGES_RESPONSES_MAPPABLE_FIELDS,
  messagesToResponsesRequest,
  ResponsesToMessagesSse,
} from '../src/responsesMessages.mjs';
import { ALLOWED_MESSAGES_FIELDS, projectAllowedFields } from '../src/eligibility.mjs';
import { MessagesUsageExtractor, MESSAGES_DIALECT } from '../src/messages.mjs';

const require = createRequire(import.meta.url);
const FIXTURES = JSON.parse(readFileSync(new URL('./responsesMessages.fixtures.json', import.meta.url), 'utf8'));

const openaiRow = (o = {}) => ({
  provider: 'openai',
  ppqModelId: 'openai/gpt-5.5',
  orSlug: 'openai/gpt-5.5',
  upstreamModelId: 'gpt-5.5',
  tier: 'default',
  serviceTier: '',
  inputPerToken: 5e-6,
  outputPerToken: 3e-5,
  cacheReadPerToken: 5e-7,
  cacheWritePerToken: null,
  supportsTools: true,
  supportsImageInput: true,
  contextLength: 1050000,
  enabled: true,
  enabledOverride: null,
  matchConfidence: 'override',
  stale: false,
  priceSource: 'openrouter-endpoints',
  verifiedAt: null,
  ...o,
});

// A Claude Code-shaped /messages body.
const claudeCode = (o = {}) => ({
  model: 'openai/gpt-5.5',
  max_tokens: 32000,
  stream: true,
  temperature: 1,
  metadata: { user_id: 'user_abc' },
  system: [
    { type: 'text', text: 'You are Claude Code.', cache_control: { type: 'ephemeral' } },
    { type: 'text', text: 'Env: darwin' },
  ],
  tools: [
    {
      name: 'Bash',
      description: 'Run a command',
      input_schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
      cache_control: { type: 'ephemeral' },
    },
  ],
  messages: [{ role: 'user', content: [{ type: 'text', text: 'list files' }] }],
  ...o,
});

const project = (payload, row = openaiRow()) => projectAllowedFields(payload, row, '/messages');

/** Feed a whole SSE body in arbitrary-size chunks; return the parsed events. */
function translate(raw, chunkSize = 97, upstreamModel = 'openai.gpt-6-luna') {
  const t = new ResponsesToMessagesSse({ upstreamModel });
  const bytes = Buffer.from(raw);
  let out = '';
  for (let i = 0; i < bytes.length; i += chunkSize) out += t.feed(bytes.subarray(i, i + chunkSize)).toString();
  out += t.finish().toString();
  return out
    .split('\n\n')
    .filter(Boolean)
    .map((block) => {
      const [ev, data] = block.split('\n');
      return { event: ev.slice('event: '.length), data: JSON.parse(data.slice('data: '.length)) };
    });
}

// ── request translation ──────────────────────────────────────────────────────

test('covers every field the shared /messages allowlist can project', () => {
  for (const key of ALLOWED_MESSAGES_FIELDS) assert.ok(MESSAGES_RESPONSES_MAPPABLE_FIELDS.has(key), key);
});

test('maps a Claude Code turn: system blocks, function tools, dropped sampling/metadata', () => {
  const { body, skip } = messagesToResponsesRequest(project(claudeCode()));
  assert.equal(skip, undefined);
  assert.deepEqual(body, {
    model: 'gpt-5.5',
    stream: true,
    store: false,
    max_output_tokens: 32000,
    input: [
      { role: 'system', content: [{ type: 'input_text', text: 'You are Claude Code.' }, { type: 'input_text', text: 'Env: darwin' }] },
      { role: 'user', content: [{ type: 'input_text', text: 'list files' }] },
    ],
    tools: [
      {
        type: 'function',
        name: 'Bash',
        description: 'Run a command',
        parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
        strict: false,
      },
    ],
  });
});

test('orders tool_use → function_call and tool_result → function_call_output around text; drops prior thinking', () => {
  const { body } = messagesToResponsesRequest(
    project(
      claudeCode({
        messages: [
          { role: 'user', content: 'list files' },
          {
            role: 'assistant',
            content: [
              { type: 'thinking', thinking: 'hmm', signature: 'sig' },
              { type: 'text', text: 'Running ls.' },
              { type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { command: 'ls' } },
            ],
          },
          {
            role: 'user',
            content: [
              { type: 'tool_result', tool_use_id: 'toolu_1', content: [{ type: 'text', text: 'a.txt' }] },
              { type: 'text', text: 'and now?' },
            ],
          },
        ],
      }),
    ),
  );
  assert.deepEqual(body.input.slice(1), [
    { role: 'user', content: [{ type: 'input_text', text: 'list files' }] },
    { role: 'assistant', content: [{ type: 'output_text', text: 'Running ls.' }] },
    { type: 'function_call', call_id: 'toolu_1', name: 'Bash', arguments: '{"command":"ls"}' },
    { type: 'function_call_output', call_id: 'toolu_1', output: 'a.txt' },
    { role: 'user', content: [{ type: 'input_text', text: 'and now?' }] },
  ]);
});

test('keeps a failed tool result recognisable, and maps images to input_image data URIs', () => {
  const { body } = messagesToResponsesRequest(
    project(
      claudeCode({
        messages: [
          { role: 'user', content: 'go' },
          { role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'Bash', input: {} }] },
          {
            role: 'user',
            content: [
              { type: 'tool_result', tool_use_id: 't', content: 'command not found', is_error: true },
              { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgo=' } },
            ],
          },
        ],
      }),
    ),
  );
  assert.deepEqual(body.input.slice(-2), [
    { type: 'function_call_output', call_id: 't', output: 'Error: command not found' },
    { role: 'user', content: [{ type: 'input_image', image_url: 'data:image/png;base64,iVBORw0KGgo=' }] },
  ]);
});

test('maps thinking budgets through the shared buckets; output_config.effort wins', () => {
  const effort = (o) => messagesToResponsesRequest(project(claudeCode(o))).body?.reasoning?.effort;
  assert.equal(effort({ thinking: { type: 'enabled', budget_tokens: 1024 } }), 'low');
  assert.equal(effort({ thinking: { type: 'enabled', budget_tokens: 8192 } }), 'medium');
  assert.equal(effort({ thinking: { type: 'enabled', budget_tokens: 31999 } }), 'high');
  assert.equal(effort({ thinking: { type: 'adaptive' } }), undefined);
  assert.equal(effort({ output_config: { effort: 'max' }, thinking: { type: 'enabled', budget_tokens: 1024 } }), 'max');
  assert.equal(effort({ output_config: { effort: 'xhigh' } }), 'xhigh');
});

test('skips what the Responses wire cannot honour, naming the field', () => {
  const bail = (o) => {
    const r = messagesToResponsesRequest(project(claudeCode(o)));
    return [r.skip, r.offendingField];
  };
  assert.deepEqual(bail({ thinking: { type: 'disabled' } }), ['unmappable_field', 'thinking.disabled']);
  assert.deepEqual(bail({ output_config: { format: { type: 'json_schema' } } }), ['unmappable_field', 'output_config.format']);
  assert.deepEqual(bail({ output_config: { effort: 'turbo' } }), ['unmappable_field', 'output_config.effort']);
  assert.deepEqual(bail({ stop_sequences: ['END'] }), ['unmappable_field', 'stop_sequences']);
  assert.deepEqual(bail({ stream: false }), ['stream_required', undefined]);
  assert.deepEqual(bail({ tools: [{ name: 'x', input_schema: {}, defer_loading: true }] }), ['unmappable_field', 'tools.defer_loading']);
  assert.deepEqual(bail({ tool_choice: { type: 'wat' } }), ['unmappable_field', 'tool_choice']);
});

test('maps tool_choice, including disable_parallel_tool_use', () => {
  const choose = (tool_choice) => messagesToResponsesRequest(project(claudeCode({ tool_choice }))).body;
  assert.equal(choose({ type: 'auto' }).tool_choice, 'auto');
  assert.equal(choose({ type: 'any' }).tool_choice, 'required');
  assert.equal(choose({ type: 'none' }).tool_choice, 'none');
  const forced = choose({ type: 'tool', name: 'Bash', disable_parallel_tool_use: true });
  assert.deepEqual(forced.tool_choice, { type: 'function', name: 'Bash' });
  assert.equal(forced.parallel_tool_calls, false);
});

test('never mutates the projected body (shared with the OpenRouter fallback)', () => {
  const payload = claudeCode();
  const before = JSON.stringify(payload);
  messagesToResponsesRequest(project(payload));
  assert.equal(JSON.stringify(payload), before);
});

test('the dialect object: an openai candidate is translated (with OUR safety_identifier), a Fireworks one projected as is', () => {
  const { createHmac } = require('node:crypto');
  const body = claudeCode();
  const translated = MESSAGES_DIALECT.directProject(body, openaiRow(), { creditId: 'cred_1', safetySecret: 's3cret' });
  assert.equal(translated.skip, undefined);
  assert.equal(translated.body.model, 'gpt-5.5');
  assert.equal(translated.body.store, false);
  assert.equal(translated.body.safety_identifier, createHmac('sha256', 's3cret').update('cred_1').digest('hex'));
  assert.equal(MESSAGES_DIALECT.directProject(body, openaiRow(), {}).body.safety_identifier, undefined);
  const fw = MESSAGES_DIALECT.directProject(body, openaiRow({ provider: 'fireworks', upstreamModelId: 'accounts/fireworks/models/kimi-k3' }));
  assert.equal(fw.body.model, 'accounts/fireworks/models/kimi-k3');
  assert.ok(Array.isArray(fw.body.messages), 'a native speaker gets the Messages body');
  // Paths: the OpenAI candidate's own /v1/responses; Fireworks' /messages beside its chat path.
  assert.equal(MESSAGES_DIALECT.directPathFor('/v1/responses', 'openai'), '/v1/responses');
  assert.equal(MESSAGES_DIALECT.directPathFor('/inference/v1/chat/completions', 'openai'), null);
  assert.equal(MESSAGES_DIALECT.directPathFor('/inference/v1/chat/completions', 'fireworks'), '/inference/v1/messages');
  // Translator only for openai.
  assert.ok(MESSAGES_DIALECT.directTranslator({ provider: 'openai', upstream_model: 'gpt-5.5' }) instanceof ResponsesToMessagesSse);
  assert.equal(MESSAGES_DIALECT.directTranslator({ provider: 'fireworks', upstream_model: 'x' }), null);
});

// ── response stream translation (real recorded bodies) ───────────────────────

test('translates the recorded text + tool-call stream into a well-formed Anthropic stream', () => {
  const events = translate(FIXTURES.toolCallStream);
  assert.deepEqual(events.map((e) => e.event), [
    'message_start',
    'content_block_start',
    'content_block_delta',
    'content_block_stop',
    'content_block_start',
    'content_block_delta',
    'content_block_delta',
    'content_block_delta',
    'content_block_delta',
    'content_block_delta',
    'content_block_stop',
    'message_delta',
    'message_stop',
  ]);
  for (const e of events) assert.equal(e.data.type, e.event);
  assert.equal(events[0].data.message.model, 'openai.gpt-6-luna'); // the wire echo, for the tripwire
  assert.deepEqual(events[1].data.content_block, { type: 'text', text: '' });
  assert.deepEqual(events[2].data.delta, { type: 'text_delta', text: 'checking' });
  assert.equal(events[4].data.content_block.type, 'tool_use');
  assert.equal(events[4].data.content_block.id, 'call_736493e001e35d05b53a691398829556');
  assert.equal(events[4].data.content_block.name, 'get_weather');
  const json = events.filter((e) => e.data.delta?.type === 'input_json_delta').map((e) => e.data.delta.partial_json).join('');
  assert.deepEqual(JSON.parse(json), { city: 'Paris' });
  assert.deepEqual(events[11].data, {
    type: 'message_delta',
    delta: { stop_reason: 'tool_use', stop_sequence: null },
    usage: { input_tokens: 49, output_tokens: 26, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
  });
});

test('is chunk-boundary independent', () => {
  const strip = (events) => events.map((e) => ({ ...e, data: { ...e.data, message: undefined } }));
  const whole = strip(translate(FIXTURES.toolCallStream, 1 << 20));
  for (const size of [1, 7, 64]) assert.deepEqual(strip(translate(FIXTURES.toolCallStream, size)), whole, `chunk ${size}`);
});

test('bills a warm-cache turn in the additive convention the Messages extractor and hp expect', () => {
  // Recorded: input_tokens 6015 of which cached_tokens 6013, output 5.
  const events = translate(FIXTURES.warmCacheStream);
  const delta = events.find((e) => e.event === 'message_delta').data;
  assert.equal(delta.delta.stop_reason, 'end_turn');
  assert.deepEqual(delta.usage, { input_tokens: 2, output_tokens: 5, cache_read_input_tokens: 6013, cache_creation_input_tokens: 0 });
  // The relay's extractor reads the translated frames: what hp is told.
  const x = new MessagesUsageExtractor();
  for (const e of events) x.feed(`data: ${JSON.stringify(e.data)}`);
  assert.equal(x.result.inputTokens, 2);
  assert.equal(x.result.cacheReadTokens, 6013);
  assert.equal(x.result.outputTokens, 5);
  assert.equal(x.result.servedModel, 'openai.gpt-6-luna');
});

test('a dated OpenAI echo rides message_start as the served model; the key rewriter hides it from the client', () => {
  const raw =
    'data: {"type":"response.created","response":{"model":"gpt-5.5-2026-04-23","usage":null}}\n\n' +
    'data: {"type":"response.output_text.delta","item_id":"m","output_index":0,"delta":"pong"}\n\n' +
    'data: {"type":"response.completed","response":{"model":"gpt-5.5-2026-04-23","usage":{"input_tokens":12,"output_tokens":3,"input_tokens_details":{"cached_tokens":4}}}}\n\n';
  const events = translate(raw, 97, 'gpt-5.5');
  assert.equal(events[0].data.message.model, 'gpt-5.5-2026-04-23');
  const t = new ResponsesToMessagesSse({ upstreamModel: 'gpt-5.5' });
  const out = t.feed(Buffer.from(raw)).toString() + t.finish().toString();
  assert.equal(t.wireModel, 'gpt-5.5-2026-04-23');
  const rw = MESSAGES_DIALECT.directRewriter({ provider: 'openai', upstreamModel: 'gpt-5.5', orSlug: 'openai/gpt-5.5' });
  const client = rw.feed(Buffer.from(out)).toString() + rw.finish().toString();
  assert.ok(client.includes('"model":"openai/gpt-5.5"'), client);
  assert.ok(!client.includes('2026-04-23'));
});

test('maps a max_output_tokens cut to stop_reason max_tokens', () => {
  const raw =
    'data: {"type":"response.created","response":{"model":"gpt-6-astra","usage":null}}\n\n' +
    'data: {"type":"response.output_text.delta","item_id":"m","output_index":0,"delta":"Hel"}\n\n' +
    'data: {"type":"response.incomplete","response":{"model":"gpt-6-astra","incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":10,"output_tokens":3,"input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0}}}}\n\n';
  const events = translate(raw);
  assert.deepEqual(events.map((e) => e.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop']);
  assert.equal(events[4].data.delta.stop_reason, 'max_tokens');
});

test('turns response.failed and a truncated stream into a terminal Anthropic error event', () => {
  const failed = translate(
    'data: {"type":"response.created","response":{"model":"gpt-6-astra"}}\n\n' +
      'data: {"type":"response.failed","response":{"error":{"message":"The server had an error"}}}\n\n' +
      'data: {"type":"response.output_text.delta","item_id":"m","delta":"ignored after the error"}\n\n',
  );
  assert.deepEqual(failed.map((e) => e.event), ['message_start', 'error']);
  assert.deepEqual(failed[1].data, { type: 'error', error: { type: 'api_error', message: 'upstream The server had an error' } });

  const truncated = translate('data: {"type":"response.output_text.delta","item_id":"m","delta":"Hi"}\n\n');
  assert.deepEqual(truncated.map((e) => e.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'error']);
});
