// The response restorer holds bytes it cannot release yet: a whole JSON body,
// or one incomplete SSE event. `maxBytes` bounds that hold, so an upstream
// that never ends an event (or sends an oversize body) fails the answer
// instead of growing the buffer without limit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createResponseRestorer, RestoreOverflowError } from '../src/pii/pipeline.mjs';
import { pseudonymize } from '../src/pii/core.mjs';
import * as messages from '../src/pii/dialects/messages.mjs';

// Fictional PII only.
const { mapping: MAPPING } = pseudonymize(['Jane Roe'], [[{ start: 0, end: 8, cls: 'PERSON' }]]);
const sse = (ev) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;

test('SSE: complete events of any total size flow; one held event past the bound throws', () => {
  const r = createResponseRestorer(messages, MAPPING, 'text/event-stream', { maxBytes: 64 });
  const ping = sse({ type: 'ping' });
  let out = '';
  for (let i = 0; i < 20; i++) out += r.push(Buffer.from(ping)).toString('utf8');
  assert.equal(out, ping.repeat(20), 'the bound is on what is held, not on what passed');
  assert.throws(() => r.push(Buffer.from(`data: ${'x'.repeat(80)}`)), RestoreOverflowError);
});

test('JSON: a body within the bound restores; one past it throws on the push that crosses it', () => {
  const body = JSON.stringify({ type: 'message', content: [{ type: 'text', text: 'OK' }] });
  const ok = createResponseRestorer(messages, MAPPING, 'application/json', { maxBytes: body.length });
  ok.push(Buffer.from(body));
  assert.deepEqual(JSON.parse(ok.finish().toString('utf8')), JSON.parse(body));
  const over = createResponseRestorer(messages, MAPPING, 'application/json', { maxBytes: body.length - 1 });
  over.push(Buffer.from(body.slice(0, 10)));
  assert.throws(() => over.push(Buffer.from(body.slice(10))), RestoreOverflowError);
});

test('no bound given: unbounded, as before', () => {
  const r = createResponseRestorer(messages, MAPPING, 'application/json');
  r.push(Buffer.alloc(1 << 20, 0x20));
  assert.ok(r.finish().length > 0);
});
