import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createTraceRecorder,
  sanitizeTrace,
  classifyFailure,
  ROUTE_PROVIDERS,
  STREAM_ENDS,
  MARKS,
} from '../src/trace.mjs';

// The trace is a containment boundary like the error report: this enclave sees
// prompts in the clear and nothing derived from one may ride out on a settle
// row. These tests prove that whatever reaches the recorder, only allowlisted
// fields in allowlisted shapes come out of build() / sanitizeTrace().

/** A clock that returns the queued instants in order, then the last one. */
function fakeClock(instants) {
  let i = 0;
  return () => instants[Math.min(i++, instants.length - 1)];
}

const TRACE_KEYS = [
  'client_request_id', 'user_agent', 'client_ip', 'streaming', 'ehbp',
  't_authorize_ms', 't_upstream_connect_ms', 't_first_token_ms', 't_total_ms',
  'bytes_out', 'route', 'stream_end', 'max_tokens_cap_applied', 'max_tokens_cap',
  'enclave',
];

/** The reference case: a normal streamed OpenRouter request. */
function normalOpenRouterTrace() {
  // start=1000, authorized=1085, upstreamHeaders=1400, firstByte=1620, end=4200
  const rec = createTraceRecorder({ now: fakeClock([1000, 1085, 1400, 1620, 4200]) });
  rec.setClient({ requestId: 'req-abc.123', userAgent: 'openai-node/4.52.0 (linux)' });
  rec.setEnclave({ version: '0.1.0', worker: 2, box: 'i-0abc123def456' });
  rec.setEhbp(false);
  rec.setStreaming(true);
  rec.mark('authorized');
  rec.setMaxTokensCap({ applied: true, cap: 4096 });
  rec.mark('upstreamHeaders');
  rec.setRoute({
    chosen: 'openrouter',
    upstreamHost: 'openrouter.ai',
    apiStyle: 'openai',
    skipped: [{ provider: 'fireworks', reason: 'no_tunnel_or_key', field: undefined }],
    failed: [],
  });
  rec.addBytes(321); // receipt line
  rec.mark('firstByte');
  rec.addBytes(4500);
  rec.mark('firstByte'); // repeated on every chunk; must not move
  rec.setStreamEnd('clean');
  rec.mark('end');
  return rec;
}

test('normal streamed OpenRouter request produces the documented trace', () => {
  const trace = normalOpenRouterTrace().build();
  assert.deepEqual(trace, {
    client_request_id: 'req-abc.123',
    user_agent: 'openai-node/4.52.0 (linux)',
    streaming: true,
    ehbp: false,
    t_authorize_ms: 85,
    t_upstream_connect_ms: 400,
    t_first_token_ms: 620,
    t_total_ms: 3200,
    bytes_out: 4821,
    route: {
      chosen: 'openrouter',
      upstream_host: 'openrouter.ai',
      api_style: 'openai',
      skipped: [{ provider: 'fireworks', reason: 'no_tunnel_or_key' }],
      failed: [],
    },
    stream_end: 'clean',
    max_tokens_cap_applied: true,
    max_tokens_cap: 4096,
    enclave: { version: '0.1.0', worker: 2, box: 'i-0abc123def456' },
  });
  // Printed so the wire shape is visible in the test log for the hp side.
  console.log(`TRACE_EXAMPLE ${JSON.stringify(trace)}`);
});

test('the enums are the documented vocabulary', () => {
  assert.deepEqual([...ROUTE_PROVIDERS], ['openrouter', 'fireworks', 'bedrock', 'anthropic', 'vertex']);
  assert.deepEqual([...STREAM_ENDS], ['clean', 'upstream_error', 'client_abort', 'cap_hit']);
  assert.deepEqual([...MARKS], ['start', 'authorized', 'upstreamHeaders', 'firstByte', 'end']);
});

// ── caller-controlled scalars ─────────────────────────────────────────────

test('a caller request id that fails the pattern is dropped', () => {
  const bad = [
    'has spaces',
    'a'.repeat(65),
    'quote"inside',
    'json{"a":1}',
    'my prompt: how do I…',
    'x/y',
    '',
    42,
    null,
    ['req-1'],
  ];
  for (const requestId of bad) {
    const rec = createTraceRecorder({ now: () => 0 });
    rec.setClient({ requestId });
    assert.equal(rec.build().client_request_id, undefined, `accepted ${JSON.stringify(requestId)}`);
  }
});

test('a caller request id in the allowed shape is kept', () => {
  for (const requestId of ['req-abc.123', 'A_b-c', '0', 'x'.repeat(64), 'enc-1787574285876-k3d9f1']) {
    const rec = createTraceRecorder({ now: () => 0 });
    rec.setClient({ requestId });
    assert.equal(rec.build().client_request_id, requestId);
  }
});

test('a 5000-char user agent is truncated to 200 printable chars', () => {
  const ua = 'Mozilla/5.0 '.repeat(500);
  assert.ok(ua.length >= 5000);
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setClient({ userAgent: ua });
  const out = rec.build().user_agent;
  assert.equal(out.length, 200);
  assert.equal(out, ua.slice(0, 200));
  assert.match(out, /^[\x20-\x7E]+$/);
});

test('a user agent with non-printable or non-ASCII bytes is omitted', () => {
  for (const ua of ['curl/8.0\n', 'ok\x00bad', 'Mozilla ✓', '\t', 'é', '']) {
    const rec = createTraceRecorder({ now: () => 0 });
    rec.setClient({ userAgent: ua });
    assert.equal(rec.build().user_agent, undefined, `accepted ${JSON.stringify(ua)}`);
  }
});

test('a user agent whose first 200 chars are printable is kept even if later bytes are not', () => {
  const ua = 'x'.repeat(200) + '\n' + 'é';
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setClient({ userAgent: ua });
  assert.equal(rec.build().user_agent, 'x'.repeat(200));
});

test('non-string user agents and request ids are ignored', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setClient({ userAgent: { toString: () => 'x' }, requestId: 12, clientIp: 7 });
  const t = rec.build();
  assert.equal(t.user_agent, undefined);
  assert.equal(t.client_request_id, undefined);
  assert.equal(t.client_ip, undefined);
});

test('client_ip must be label-shaped; omitted when absent', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setClient({ clientIp: '203.0.113.9' });
  assert.equal(rec.build().client_ip, '203.0.113.9');
  rec.setClient({ clientIp: '2001:db8::1' });
  assert.equal(rec.build().client_ip, '2001:db8::1');
  rec.setClient({ clientIp: 'not an ip at all' });
  assert.equal(rec.build().client_ip, undefined);
  rec.setClient({});
  assert.equal('client_ip' in rec.build(), false);
});

// ── booleans ──────────────────────────────────────────────────────────────

test('streaming defaults to true and ehbp to false; only `true` sets either', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  assert.equal(rec.build().streaming, true);
  assert.equal(rec.build().ehbp, false);
  rec.setStreaming('yes');
  rec.setEhbp('yes');
  assert.equal(rec.build().streaming, false);
  assert.equal(rec.build().ehbp, false);
  rec.setStreaming(true);
  rec.setEhbp(true);
  assert.equal(rec.build().streaming, true);
  assert.equal(rec.build().ehbp, true);
});

// ── timings ───────────────────────────────────────────────────────────────

test('timings for marks never made are omitted; t_total measures to now', () => {
  const rec = createTraceRecorder({ now: fakeClock([1000, 1500]) });
  const t = rec.build();
  assert.equal(t.t_authorize_ms, undefined);
  assert.equal(t.t_upstream_connect_ms, undefined);
  assert.equal(t.t_first_token_ms, undefined);
  assert.equal(t.t_total_ms, 500);
  assert.equal(t.bytes_out, 0);
});

test('marks are first-wins and unknown marks are ignored', () => {
  const rec = createTraceRecorder({ now: fakeClock([0, 10, 20, 30, 40, 50]) });
  rec.mark('authorized'); // 10
  rec.mark('authorized'); // would be 20; ignored
  rec.mark('bogus'); // ignored, consumes no clock tick
  rec.mark(undefined);
  rec.mark('end'); // 20
  const t = rec.build();
  assert.equal(t.t_authorize_ms, 10);
  assert.equal(t.t_total_ms, 20);
});

test('a clock that goes backwards clamps to zero rather than exporting a negative', () => {
  const rec = createTraceRecorder({ now: fakeClock([1000, 900, 800]) });
  rec.mark('authorized');
  rec.mark('end');
  const t = rec.build();
  assert.equal(t.t_authorize_ms, 0);
  assert.equal(t.t_total_ms, 0);
});

test('a broken clock produces integers, never NaN', () => {
  const rec = createTraceRecorder({ now: () => NaN });
  rec.mark('authorized');
  rec.mark('end');
  const t = rec.build();
  assert.equal(t.t_authorize_ms, 0);
  assert.equal(t.t_total_ms, 0);
});

test('fractional millisecond clocks round to integers', () => {
  const rec = createTraceRecorder({ now: fakeClock([0.4, 12.6]) });
  rec.mark('end');
  assert.equal(rec.build().t_total_ms, 12);
});

// ── bytes ─────────────────────────────────────────────────────────────────

test('addBytes sums positive finite numbers and ignores everything else', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.addBytes(10);
  rec.addBytes(0);
  rec.addBytes(-5);
  rec.addBytes(NaN);
  rec.addBytes(Infinity);
  rec.addBytes('100');
  rec.addBytes(2.5);
  assert.equal(rec.build().bytes_out, 13); // 10 + 2.5 rounded
});

// ── route ─────────────────────────────────────────────────────────────────

test('route is dropped entirely when the chosen provider is not in the enum', () => {
  for (const chosen of ['OpenRouter', 'groq', 'api.openai.com', '', undefined, 3]) {
    const rec = createTraceRecorder({ now: () => 0 });
    rec.setRoute({ chosen, upstreamHost: 'openrouter.ai' });
    assert.equal(rec.build().route, undefined, `accepted ${JSON.stringify(chosen)}`);
  }
});

test('route accepts every documented provider', () => {
  for (const chosen of ROUTE_PROVIDERS) {
    const rec = createTraceRecorder({ now: () => 0 });
    rec.setRoute({ chosen });
    assert.deepEqual(rec.build().route, { chosen, skipped: [], failed: [] });
  }
});

test('upstream_host and api_style are label-checked and omitted when unusable', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setRoute({ chosen: 'anthropic', upstreamHost: 'not a host name', apiStyle: 'with space' });
  assert.deepEqual(rec.build().route, { chosen: 'anthropic', skipped: [], failed: [] });
  rec.setRoute({ chosen: 'bedrock', upstreamHost: 'bedrock-mantle.us-east-2.api.aws', apiStyle: 'bedrock' });
  assert.deepEqual(rec.build().route, {
    chosen: 'bedrock',
    upstream_host: 'bedrock-mantle.us-east-2.api.aws',
    api_style: 'bedrock',
    skipped: [],
    failed: [],
  });
});

test('skipped candidates keep only enum-shaped provider/reason/field', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setRoute({
    chosen: 'openrouter',
    skipped: [
      { provider: 'fireworks', reason: 'unsupported_field', field: 'response_format' },
      { provider: 'anthropic', reason: 'the user asked for something weird' }, // free text → dropped
      { provider: 'vertex' }, // no reason → dropped
      { reason: 'no_tunnel_or_key' }, // no provider → dropped
      { provider: 'bedrock', reason: 'binding_violation', field: 'has spaces' }, // bad field → field omitted
      'not an object',
      null,
    ],
  });
  assert.deepEqual(rec.build().route.skipped, [
    { provider: 'fireworks', reason: 'unsupported_field', field: 'response_format' },
    { provider: 'bedrock', reason: 'binding_violation' },
  ]);
});

test('failed candidates carry a positive integer status and a derived class', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setRoute({
    chosen: 'openrouter',
    failed: [
      { provider: 'fireworks', status: 503 },
      { provider: 'anthropic', status: 429 },
      { provider: 'bedrock' }, // connect error: no status
      { provider: 'vertex', status: 0 },
      { provider: 'vertex', status: '500' }, // not a number → no status
      { provider: 'anthropic', status: 401, class: 'auth_failed' }, // explicit class honoured
      { provider: 'anthropic', status: 401, class: 'not a label' }, // bad class → derived
      { status: 500 }, // no provider → dropped
    ],
  });
  assert.deepEqual(rec.build().route.failed, [
    { provider: 'fireworks', status: 503, class: 'http_5xx' },
    { provider: 'anthropic', status: 429, class: 'http_4xx' },
    { provider: 'bedrock', class: 'connect_error' },
    { provider: 'vertex', class: 'connect_error' },
    { provider: 'vertex', class: 'connect_error' },
    { provider: 'anthropic', status: 401, class: 'auth_failed' },
    { provider: 'anthropic', status: 401, class: 'http_4xx' },
  ]);
});

test('classifyFailure buckets statuses', () => {
  assert.equal(classifyFailure(undefined), 'connect_error');
  assert.equal(classifyFailure(0), 'connect_error');
  assert.equal(classifyFailure(400), 'http_4xx');
  assert.equal(classifyFailure(499), 'http_4xx');
  assert.equal(classifyFailure(500), 'http_5xx');
  assert.equal(classifyFailure(302), 'http_other');
});

test('skipped and failed lists are capped at 8 entries', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  const many = Array.from({ length: 50 }, () => ({ provider: 'fireworks', reason: 'x', status: 500 }));
  rec.setRoute({ chosen: 'openrouter', skipped: many, failed: many });
  const { route } = rec.build();
  assert.equal(route.skipped.length, 8);
  assert.equal(route.failed.length, 8);
});

test('non-array candidate lists become empty arrays', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setRoute({ chosen: 'openrouter', skipped: 'nope', failed: { provider: 'x' } });
  assert.deepEqual(rec.build().route, { chosen: 'openrouter', skipped: [], failed: [] });
});

// ── stream end ────────────────────────────────────────────────────────────

test('stream_end is first-writer-wins: a client abort survives the later upstream end', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  assert.equal(rec.build().stream_end, undefined);
  rec.setStreamEnd('client_abort');
  rec.setStreamEnd('clean');
  assert.equal(rec.build().stream_end, 'client_abort');
  assert.equal(rec.streamEnd(), 'client_abort');
});

test('an unknown stream_end is ignored and does not block a later valid one', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  rec.setStreamEnd('exploded');
  rec.setStreamEnd(null);
  assert.equal(rec.build().stream_end, undefined);
  rec.setStreamEnd('cap_hit');
  assert.equal(rec.build().stream_end, 'cap_hit');
});

// ── max_tokens cap ────────────────────────────────────────────────────────

test('max_tokens cap: applied flag is boolean, cap is a positive integer or omitted', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  assert.equal(rec.build().max_tokens_cap_applied, false);
  assert.equal('max_tokens_cap' in rec.build(), false);
  rec.setMaxTokensCap({ applied: true, cap: 0 });
  assert.equal(rec.build().max_tokens_cap_applied, true);
  assert.equal('max_tokens_cap' in rec.build(), false);
  rec.setMaxTokensCap({ applied: 'true', cap: 1234.4 });
  assert.equal(rec.build().max_tokens_cap_applied, false);
  assert.equal(rec.build().max_tokens_cap, 1234);
});

// ── enclave identity ──────────────────────────────────────────────────────

test('enclave identity: label-checked version/box, worker defaults to 0', () => {
  const rec = createTraceRecorder({ now: () => 0 });
  assert.equal(rec.build().enclave, undefined);
  rec.setEnclave({ version: '0.1.0' });
  assert.deepEqual(rec.build().enclave, { version: '0.1.0', worker: 0 });
  rec.setEnclave({ version: 'v 1', worker: 3, box: 'i-0123456789abcdef0' });
  assert.deepEqual(rec.build().enclave, { worker: 3, box: 'i-0123456789abcdef0' });
  rec.setEnclave({ version: '0.1.0', worker: -1, box: 'box id with spaces' });
  assert.deepEqual(rec.build().enclave, { version: '0.1.0', worker: 0 });
});

// ── sanitizeTrace as the boundary ─────────────────────────────────────────

test('sanitizeTrace rejects non-objects', () => {
  assert.equal(sanitizeTrace(null), null);
  assert.equal(sanitizeTrace(undefined), null);
  assert.equal(sanitizeTrace('trace'), null);
  assert.equal(sanitizeTrace(7), null);
});

test('sanitizeTrace never emits a key outside the allowlist, whatever comes in', () => {
  const t = sanitizeTrace({
    prompt: 'my bank password is hunter2',
    messages: [{ role: 'user', content: 'secret' }],
    model: 'anthropic/claude-opus-5',
    error: 'Invalid prompt: "secret"',
    client_request_id: 'ok-1',
    route: { chosen: 'openrouter', prompt: 'leak', skipped: [{ provider: 'fireworks', reason: 'x', prompt: 'leak' }] },
    enclave: { version: '1', prompt: 'leak' },
  });
  for (const k of Object.keys(t)) assert.ok(TRACE_KEYS.includes(k), `unexpected key ${k}`);
  assert.deepEqual(Object.keys(t.route).sort(), ['chosen', 'failed', 'skipped']);
  assert.deepEqual(t.route.skipped, [{ provider: 'fireworks', reason: 'x' }]);
  assert.deepEqual(Object.keys(t.enclave).sort(), ['version', 'worker']);
  assert.equal(JSON.stringify(t).includes('secret'), false);
  assert.equal(JSON.stringify(t).includes('leak'), false);
  assert.equal(JSON.stringify(t).includes('hunter2'), false);
});

test('sanitizeTrace on an empty object yields the required fields with safe defaults', () => {
  assert.deepEqual(sanitizeTrace({}), {
    streaming: false,
    ehbp: false,
    t_total_ms: 0,
    bytes_out: 0,
    max_tokens_cap_applied: false,
  });
});

test('sanitizeTrace is idempotent on the recorder output', () => {
  const t = normalOpenRouterTrace().build();
  assert.deepEqual(sanitizeTrace(t), t);
});

test('sanitizeTrace coerces numeric fields: strings, negatives, NaN, floats', () => {
  const t = sanitizeTrace({
    t_authorize_ms: '85',
    t_upstream_connect_ms: -1,
    t_first_token_ms: NaN,
    t_total_ms: 12.7,
    bytes_out: Infinity,
    max_tokens_cap: -5,
  });
  assert.equal(t.t_authorize_ms, undefined);
  assert.equal(t.t_upstream_connect_ms, undefined);
  assert.equal(t.t_first_token_ms, undefined);
  assert.equal(t.t_total_ms, 13);
  assert.equal(t.bytes_out, 0);
  assert.equal(t.max_tokens_cap, undefined);
});

test('every string that leaves satisfies the label shape or its own tighter pattern', () => {
  const LABEL = /^[a-zA-Z0-9._:/@-]{1,96}$/;
  const t = normalOpenRouterTrace().build();
  const walk = (v, path) => {
    if (typeof v === 'string') {
      if (path === 'user_agent') assert.match(v, /^[\x20-\x7E]{1,200}$/);
      else if (path === 'client_request_id') assert.match(v, /^[A-Za-z0-9._-]{1,64}$/);
      else assert.match(v, LABEL, `${path}=${v}`);
    } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, path ? `${path}.${k}` : k);
  };
  walk(t, '');
});
