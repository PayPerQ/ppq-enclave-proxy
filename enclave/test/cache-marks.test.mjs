import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addCachePromptMarks } from '../src/routing.mjs';

// addCachePromptMarks — breakpoint placement, byte-synced with horse-power
// services/models.service.ts (see models.service.test.ts there). The routing
// conformance gate in hp runs these shapes through BOTH copies; this file
// pins the enclave copy's own contract (hp #1116).

const marks = (content) => (Array.isArray(content) ? content.filter((p) => p.cache_control) : []);
const countMarks = (messages) => (JSON.stringify(messages).match(/cache_control/g) || []).length;
const toolCall = (id) => ({
  role: 'assistant',
  content: '',
  tool_calls: [{ id, type: 'function', function: { name: 'f', arguments: '{}' } }],
});

test('chat: first message and last two user messages (unchanged contract)', () => {
  const messages = [
    { role: 'system', content: 'You are helpful.' },
    { role: 'user', content: 'first question' },
    { role: 'assistant', content: 'answer' },
    { role: 'user', content: 'second question' },
    { role: 'user', content: 'third question' },
  ];
  addCachePromptMarks(messages);
  assert.equal(marks(messages[0].content).length, 1);
  assert.equal(marks(messages[1].content).length, 0);
  assert.equal(marks(messages[3].content).length, 1);
  assert.equal(marks(messages[4].content).length, 1);
  assert.equal(countMarks(messages), 3);
});

test('native tool loop (OpenAI dialect): first message, user prompt and the LAST tool result', () => {
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'do the thing' },
    toolCall('c1'),
    { role: 'tool', tool_call_id: 'c1', content: 'result one' },
    toolCall('c2'),
    { role: 'tool', tool_call_id: 'c2', content: 'result two' },
  ];
  addCachePromptMarks(messages);
  assert.equal(marks(messages[0].content).length, 1);
  assert.equal(marks(messages[1].content).length, 1);
  assert.equal(messages[3].content, 'result one');
  assert.deepEqual(messages[5].content, [
    { type: 'text', text: 'result two', cache_control: { type: 'ephemeral' } },
  ]);
  assert.equal(countMarks(messages), 3);
});

test('caps injected marks at 3: the earliest user anchor yields to the tail', () => {
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'first' },
    { role: 'assistant', content: 'ok' },
    { role: 'user', content: 'second' },
    toolCall('c1'),
    { role: 'tool', tool_call_id: 'c1', content: 'result' },
  ];
  addCachePromptMarks(messages);
  assert.equal(marks(messages[0].content).length, 1);
  assert.equal(messages[1].content, 'first');
  assert.equal(marks(messages[3].content).length, 1);
  assert.equal(marks(messages[5].content).length, 1);
  assert.equal(countMarks(messages), 3);
});

test('Roo/Cline-style loops (tool results inside user turns) keep exactly the old marks', () => {
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: '<task>go</task>' },
    { role: 'assistant', content: '<read_file><path>a</path></read_file>' },
    { role: 'user', content: '[read_file result] contents' },
    { role: 'assistant', content: '<write_file>…</write_file>' },
    { role: 'user', content: '[write_file result] ok' },
  ];
  addCachePromptMarks(messages);
  assert.equal(marks(messages[0].content).length, 1);
  assert.equal(messages[1].content, '<task>go</task>');
  assert.equal(marks(messages[3].content).length, 1);
  assert.equal(marks(messages[5].content).length, 1);
  assert.equal(countMarks(messages), 3);
});

test('translated Messages dialect: the mark rides the tool_result block, never the nested text', () => {
  const messages = [
    { role: 'user', content: [{ type: 'text', text: 'go' }] },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'c1', name: 'f', input: {} }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'text', text: 'one' }] }] },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'c2', name: 'f', input: {} }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c2', content: [{ type: 'text', text: 'two' }] }] },
  ];
  addCachePromptMarks(messages);
  assert.deepEqual(messages[0].content[0].cache_control, { type: 'ephemeral' });
  assert.deepEqual(messages[2].content[0].cache_control, { type: 'ephemeral' });
  assert.deepEqual(messages[4].content[0].cache_control, { type: 'ephemeral' });
  assert.equal(messages[4].content[0].content[0].cache_control, undefined);
  assert.equal(JSON.stringify(messages[3]).includes('cache_control'), false);
  assert.equal(countMarks(messages), 3);
});

test('walks back past an unmarkable tail (empty tool output)', () => {
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'go' },
    toolCall('c1'),
    { role: 'tool', tool_call_id: 'c1', content: 'real output' },
    toolCall('c2'),
    { role: 'tool', tool_call_id: 'c2', content: '' },
  ];
  addCachePromptMarks(messages);
  assert.equal(marks(messages[3].content).length, 1);
  assert.equal(messages[5].content, '');
  assert.equal(countMarks(messages), 3);
});

test('a translated tool_result holding only an empty text block is never a host (#674)', () => {
  const messages = [
    { role: 'user', content: 'go' },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'c1', name: 'f', input: {} }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'text', text: '' }] }] },
  ];
  addCachePromptMarks(messages);
  assert.equal(messages[2].content[0].cache_control, undefined);
  assert.equal(countMarks(messages), 1);
});

test('image-only and empty messages are never marked, never synthesized (#674)', () => {
  const messages = [
    { role: 'system', content: '' },
    { role: 'user', content: [{ type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } }] },
  ];
  addCachePromptMarks(messages);
  assert.equal(countMarks(messages), 0);
  assert.equal(messages[1].content.length, 1);
});

test('a caller mark nested inside a tool_result block disables injection too', () => {
  const messages = [
    { role: 'user', content: 'go' },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'c1', name: 'f', input: {} }] },
    {
      role: 'user',
      content: [
        { type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'text', text: 'r', cache_control: { type: 'ephemeral' } }] },
      ],
    },
  ];
  addCachePromptMarks(messages);
  assert.equal(countMarks(messages), 1);
  assert.equal(messages[0].content, 'go');
});

test('a caller mark anywhere disables injection entirely', () => {
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'go' },
    toolCall('c1'),
    { role: 'tool', tool_call_id: 'c1', content: 'r', cache_control: { type: 'ephemeral' } },
  ];
  addCachePromptMarks(messages);
  assert.equal(countMarks(messages), 1);
});

test('non-array and empty input are no-ops', () => {
  assert.equal(addCachePromptMarks(undefined), undefined);
  assert.equal(addCachePromptMarks([]), undefined);
});
