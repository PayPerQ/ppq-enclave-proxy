// The receipt's job is to be believable and harmless: it must name the upstream
// the enclave's TLS actually validated against, and it must never damage a
// response that would otherwise have been fine.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RECEIPT_PREFIX,
  RECEIPT_VERSION,
  buildReceipt,
  canCarryReceipt,
  formatReceiptLine,
  receiptBytes,
} from '../src/receipt.mjs';

const directSpec = {
  isDirect: true,
  provider: 'Anthropic',
  upstreamModel: 'claude-sonnet-5-20260101',
  orSlug: 'anthropic/claude-sonnet-5',
  opts: { servername: 'api.anthropic.com', path: '/v1/messages' },
};

const orSpec = {
  isDirect: false,
  opts: { servername: 'openrouter.ai', path: '/api/v1/chat/completions' },
};

test('names the host the enclave validated TLS against', () => {
  // The load-bearing field. It is also the field horse-power controls, which is
  // exactly why stating it is worth anything.
  const r = buildReceipt({ requestedModel: 'anthropic/claude-sonnet-5', spec: directSpec, statusCode: 200 });
  assert.equal(r.upstream, 'api.anthropic.com');
  assert.equal(r.route, 'direct');
  assert.equal(r.provider, 'Anthropic');
});

test('reveals the wire model id the response rewriter hides', () => {
  // directResponseRewriter rewrites the upstream model id to the public slug so
  // a direct provider is invisible in the stream. The receipt is the one place
  // that says what was really sent.
  const r = buildReceipt({ requestedModel: 'anthropic/claude-sonnet-5', spec: directSpec, statusCode: 200 });
  assert.equal(r.upstream_model, 'claude-sonnet-5-20260101');
  assert.notEqual(r.upstream_model, r.requested_model);
});

test('admits that OpenRouter picks its own provider', () => {
  // A receipt that let a reader believe an OR route pins the provider would be
  // worse than no receipt.
  const or = buildReceipt({ requestedModel: 'x/y', spec: orSpec, statusCode: 200 });
  assert.equal(or.upstream_selects_provider, true);
  assert.equal(or.route, 'openrouter');

  const direct = buildReceipt({ requestedModel: 'x/y', spec: directSpec, statusCode: 200 });
  assert.equal(direct.upstream_selects_provider, false);
});

test('explains why earlier candidates were passed over', () => {
  const r = buildReceipt({
    requestedModel: 'x/y',
    spec: orSpec,
    statusCode: 200,
    skipped: [{ provider: 'fireworks', reason: 'unsupported_field', field: 'plugins' }],
    failed: [{ provider: 'bedrock', status: 503 }],
  });
  assert.deepEqual(r.skipped, [
    { provider: 'fireworks', reason: 'unsupported_field', field: 'plugins' },
  ]);
  assert.deepEqual(r.failed, [{ provider: 'bedrock', status: 503 }]);
});

test('omits an absent field rather than emitting null noise', () => {
  const r = buildReceipt({
    requestedModel: 'x/y',
    spec: orSpec,
    statusCode: 200,
    skipped: [{ provider: 'p', reason: 'no_tunnel_or_key' }],
  });
  assert.equal('field' in r.skipped[0], false);
});

test('carries a version so a consumer can refuse what it cannot read', () => {
  assert.equal(buildReceipt({ spec: directSpec, statusCode: 200 }).v, RECEIPT_VERSION);
});

test('survives a spec with nothing in it', () => {
  // A receipt must never be the reason a response fails.
  const r = buildReceipt({ spec: undefined, statusCode: undefined });
  assert.equal(r.upstream, null);
  assert.equal(r.route, 'openrouter');
  assert.doesNotThrow(() => formatReceiptLine(r));
});

test('is a single SSE comment line', () => {
  const line = formatReceiptLine(buildReceipt({ spec: directSpec, statusCode: 200 }));
  assert.ok(line.startsWith(': '), 'must be an SSE comment so parsers ignore it');
  assert.ok(line.endsWith('\n\n'), 'must terminate the SSE event');
  // Exactly one comment: a stray newline inside would end the comment and inject
  // a frame into the stream the client WOULD try to parse.
  assert.equal(line.trimEnd().split('\n').length, 1);
});

test('strips newlines that would break out of the comment', () => {
  const r = buildReceipt({ requestedModel: 'a\nb', spec: directSpec, statusCode: 200 });
  const line = formatReceiptLine(r);
  assert.equal(line.trimEnd().split('\n').length, 1);
  assert.ok(!line.slice(0, -2).includes('\n'));
});

test('the payload after the marker is parseable JSON', () => {
  const line = formatReceiptLine(buildReceipt({ spec: directSpec, statusCode: 200 }));
  const json = line.slice(RECEIPT_PREFIX.length).trim();
  assert.equal(JSON.parse(json).upstream, 'api.anthropic.com');
});

test('only rides event streams, never a JSON body', () => {
  // Prepending a comment line to application/json would corrupt a response that
  // was otherwise fine — strictly worse than having no receipt.
  assert.equal(canCarryReceipt('text/event-stream'), true);
  assert.equal(canCarryReceipt('text/event-stream; charset=utf-8'), true);
  assert.equal(canCarryReceipt('application/json'), false);
  assert.equal(canCarryReceipt(undefined), false);
  assert.equal(receiptBytes('application/json', buildReceipt({ spec: directSpec })), null);
  assert.ok(Buffer.isBuffer(receiptBytes('text/event-stream', buildReceipt({ spec: directSpec }))));
});

test('carries nothing derived from the prompt or completion', () => {
  const r = buildReceipt({
    requestedModel: 'anthropic/claude-sonnet-5',
    spec: directSpec,
    statusCode: 200,
    skipped: [{ provider: 'f', reason: 'r' }],
    failed: [{ provider: 'b', status: 500 }],
  });
  // Allow-list the shape outright: a future field carrying content would be a
  // privacy regression, and this is the cheapest place to catch one.
  assert.deepEqual(Object.keys(r).sort(), [
    'failed', 'provider', 'requested_model', 'route', 'skipped',
    'upstream', 'upstream_model', 'upstream_selects_provider', 'upstream_status', 'v',
  ]);
});
