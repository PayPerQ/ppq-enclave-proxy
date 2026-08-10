import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyFreeModelStrip, applyToolStrip } from '../src/routing.mjs';

// ── applyFreeModelStrip (issue #6, driven by hp is_free) ─────────────────────

test('free strip drops paid plugins', () => {
  const p = { model: 'ppq/free', plugins: [{ id: 'web' }], messages: [] };
  applyFreeModelStrip(p);
  assert.equal('plugins' in p, false);
});

test('free strip removes the web_search tool but keeps other tools', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false); // still has a tool → tool_choice untouched-absent
});

test('free strip deletes an emptied tools array + its tool_choice', () => {
  const p = {
    model: 'ppq/free',
    tools: [{ type: 'openrouter:web_search' }],
    tool_choice: 'auto',
  };
  applyFreeModelStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

test('free strip is a no-op when there is nothing to strip', () => {
  const p = { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] };
  applyFreeModelStrip(p);
  assert.deepEqual(p, { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] });
});

// ── applyToolStrip (issue #6, driven by hp strip_tools) ──────────────────────

test('tool strip removes tools + tool_choice for an unsupported model', () => {
  const p = {
    model: 'toyco/no-tools',
    tools: [{ type: 'function', function: { name: 'f' } }],
    tool_choice: 'auto',
  };
  applyToolStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

test('tool strip leaves an empty tools array alone (matches hp length>0 guard)', () => {
  const p = { model: 'toyco/no-tools', tools: [], tool_choice: 'auto' };
  applyToolStrip(p);
  assert.deepEqual(p.tools, []);
  assert.equal(p.tool_choice, 'auto');
});

test('tool strip is a no-op when there are no tools', () => {
  const p = { model: 'toyco/no-tools', messages: [] };
  applyToolStrip(p);
  assert.deepEqual(p, { model: 'toyco/no-tools', messages: [] });
});
