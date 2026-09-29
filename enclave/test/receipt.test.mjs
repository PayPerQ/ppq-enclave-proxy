// The receipt's job is to be believable and harmless: it must name the upstream
// the enclave's TLS actually validated against, and it must never damage a
// response that would otherwise have been fine.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RECEIPT_HEADER,
  RECEIPT_PREFIX,
  RECEIPT_SIG_HEADER,
  RECEIPT_HERE,
  ReceiptGate,
  signedReceiptHeaders,
  RECEIPT_SIG_ALG,
  RECEIPT_SIG_ALG_EC,
  receiptSigAlg,
  receiptSigOptions,
  RECEIPT_SIG_PREFIX,
  RECEIPT_VERSION,
  buildReceipt,
  canCarryReceipt,
  formatReceiptLine,
  formatSignedReceiptLines,
  receiptBytes,
  signedReceiptBytes,
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
    'failed', 'issued_at', 'provider', 'request_id', 'request_id_source', 'requested_model',
    'route', 'served_model', 'skipped',
    'upstream', 'upstream_model', 'upstream_selects_provider', 'upstream_status', 'v',
  ]);
});

// ── v2: a receipt says which exchange it is about ────────────────────────────

test('two requests for the same model no longer share a receipt', () => {
  // The v1 defect, measured on production: identical bytes, so a signature
  // lifted from one request verified for the other.
  const at = new Date('2026-09-29T16:00:00.000Z');
  const a = buildReceipt({ requestedModel: 'x/y', spec: directSpec, statusCode: 200, requestId: 'one', issuedAt: at });
  const b = buildReceipt({ requestedModel: 'x/y', spec: directSpec, statusCode: 200, requestId: 'two', issuedAt: at });
  assert.notEqual(JSON.stringify(a), JSON.stringify(b));
  assert.equal(a.issued_at, '2026-09-29T16:00:00.000Z');
});

test('says whether the caller chose the request id', () => {
  // Only a caller-chosen id binds; a reader must be able to tell which it has.
  const mine = buildReceipt({ spec: directSpec, requestId: 'nonce-1', requestIdFromClient: true });
  assert.deepEqual([mine.request_id, mine.request_id_source], ['nonce-1', 'client']);
  const minted = buildReceipt({ spec: directSpec, requestId: 'enc-1790000000000-abc123' });
  assert.equal(minted.request_id_source, 'enclave');
});

test('drops a request id it cannot carry, and its source with it', () => {
  for (const bad of ['', 'a\nb', 'caf\u00e9', 'x'.repeat(129), 42, undefined]) {
    const r = buildReceipt({ spec: directSpec, requestId: bad, requestIdFromClient: true });
    assert.equal(r.request_id, null);
    assert.equal(r.request_id_source, null);
  }
});

test('states the served model only in the shape a model id has', () => {
  assert.equal(buildReceipt({ spec: directSpec, servedModel: 'claude-sonnet-5-20260101' }).served_model, 'claude-sonnet-5-20260101');
  assert.equal(buildReceipt({ spec: directSpec, servedModel: 'the answer is "yes"' }).served_model, null);
  assert.equal(buildReceipt({ spec: directSpec }).served_model, null);
});

test('an invalid date is no date', () => {
  assert.equal(buildReceipt({ spec: directSpec, issuedAt: new Date('nope') }).issued_at, null);
  assert.equal(buildReceipt({ spec: directSpec, issuedAt: '2026-09-29' }).issued_at, null);
});

// ── v2: header receipts ──────────────────────────────────────────────────────

test('a JSON response carries a signed receipt in its headers', async () => {
  const { generateKeyPairSync, verify } = await import('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const receipt = buildReceipt({ requestedModel: 'anthropic/x', spec: directSpec, statusCode: 200, requestId: 'n1', requestIdFromClient: true });
  const headers = signedReceiptHeaders('application/json', receipt, privateKey);
  const json = Buffer.from(headers[RECEIPT_HEADER], 'base64');
  const meta = JSON.parse(headers[RECEIPT_SIG_HEADER]);
  assert.deepEqual(JSON.parse(json.toString('utf8')), receipt);
  assert.equal(meta.alg, RECEIPT_SIG_ALG_EC);
  assert.equal(meta.over, 'receipt_json_utf8');
  assert.equal(verify('sha256', json, receiptSigOptions(publicKey), Buffer.from(meta.sig, 'base64')), true);
});

test('header values survive a requested model outside Latin-1', async () => {
  // writeHead throws on such a byte; the receipt must never fail a response.
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const headers = signedReceiptHeaders('application/json', buildReceipt({ requestedModel: '模型/\u2603', spec: orSpec }), privateKey);
  for (const v of Object.values(headers)) assert.match(v, /^[\x20-\x7e]+$/);
});

test('no header receipt on an event stream, and none unsigned', async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const receipt = buildReceipt({ spec: directSpec });
  assert.equal(signedReceiptHeaders('text/event-stream', receipt, privateKey), null);
  assert.equal(signedReceiptHeaders('application/json', receipt, null), null);
  assert.equal(signedReceiptHeaders('application/json', receipt, 'not a key'), null);
});

// ── v2: where the receipt goes in a stream ───────────────────────────────────

/** What a client would receive, with the receipt shown as a marker line. */
function through(gate, steps) {
  const parts = [];
  for (const [text, model] of steps) parts.push(...gate.feed(Buffer.from(text), model));
  parts.push(...gate.finish());
  return parts.map((p) => (p === RECEIPT_HERE ? '<receipt>\n\n' : p.toString('utf8'))).join('');
}

test('the receipt goes ahead of the first frame', () => {
  assert.equal(
    through(new ReceiptGate(), [['data: {"model":"m"}\n\n', 'm'], ['data: [DONE]\n\n', 'm']]),
    '<receipt>\n\ndata: {"model":"m"}\n\ndata: [DONE]\n\n',
  );
});

test('keep-alive comments pass while the receipt waits for a frame', () => {
  const gate = new ReceiptGate();
  assert.deepEqual(gate.feed(Buffer.from(': PPQ.AI PROCESSING\n\n'), undefined).map(String), [': PPQ.AI PROCESSING\n\n']);
  assert.equal(gate.written, false);
  assert.equal(
    through(gate, [['data: {"model":"m"}\n\n', 'm']]),
    '<receipt>\n\ndata: {"model":"m"}\n\n',
  );
});

test('a frame that arrives in pieces is held until it names its model', () => {
  // Found by driving the server: deciding on the first piece wrote the receipt
  // before the model was read, deciding on the second wrote it inside a line.
  const gate = new ReceiptGate();
  assert.deepEqual(gate.feed(Buffer.from(': hi\n\ndata: {"id":"1","mod'), undefined).map(String), [': hi\n\n']);
  assert.equal(
    through(gate, [['el":"m"}\n\n', 'm']]),
    '<receipt>\n\ndata: {"id":"1","model":"m"}\n\n',
  );
});

test('a complete frame that names no model still draws the receipt', () => {
  assert.equal(
    through(new ReceiptGate(), [['data: {"error":"x"}\n\n', undefined]]),
    '<receipt>\n\ndata: {"error":"x"}\n\n',
  );
});

test('a comment split across writes is not followed by a receipt mid-line', () => {
  const out = through(new ReceiptGate(), [[': PPQ.AI PROC', undefined], ['ESSING\n\ndata: {"model":"m"}\n\n', 'm']]);
  assert.equal(out, ': PPQ.AI PROCESSING\n\n<receipt>\n\ndata: {"model":"m"}\n\n');
});

test('nothing is lost or reordered, however the stream is cut', () => {
  const stream = ': a\n\n: b\r\n\r\ndata: {"model":"m","x":1}\n\nevent: e\ndata: 2\n\ndata: [DONE]\n\n';
  for (let size = 1; size <= stream.length; size++) {
    const steps = [];
    for (let i = 0; i < stream.length; i += size) {
      const seen = stream.slice(0, i + size);
      steps.push([stream.slice(i, i + size), /"model":"m"[^\n]*\n/.test(seen) ? 'm' : undefined]);
    }
    const out = through(new ReceiptGate(), steps);
    assert.equal(out.replace('<receipt>\n\n', ''), stream, `chunk size ${size}`);
    assert.equal(out.split('<receipt>').length, 2, 'exactly one receipt');
    assert.ok(out.indexOf('<receipt>') < out.indexOf('data:'), `ahead of the first frame at chunk size ${size}`);
    assert.ok(out.indexOf('<receipt>') === 0 || out[out.indexOf('<receipt>') - 1] === '\n', 'at the start of a line');
  }
});

test('a stream with no frame at all still ends with a receipt', () => {
  assert.equal(through(new ReceiptGate(), []), '<receipt>\n\n');
  assert.equal(through(new ReceiptGate(), [[': only\n\n', undefined]]), ': only\n\n<receipt>\n\n');
  // Stopped inside a comment: the blank line ends it before the receipt starts.
  assert.equal(through(new ReceiptGate(), [[': cut sho', undefined]]), ': cut sho\n\n<receipt>\n\n');
  // Stopped inside the first frame: the receipt goes ahead of what there is.
  assert.equal(through(new ReceiptGate(), [['data: {"trunc', undefined]]), '<receipt>\n\ndata: {"trunc');
});

test('a first frame is not held forever', () => {
  const gate = new ReceiptGate({ maxHeld: 32 });
  const parts = gate.feed(Buffer.from('data: ' + 'x'.repeat(64)), undefined);
  assert.equal(parts[0], RECEIPT_HERE);
  assert.equal(gate.open, true);
});

test('a response that is not an event stream is never held', () => {
  const gate = new ReceiptGate({ carries: false });
  const body = Buffer.from('{"data: ":"not a frame"');
  assert.deepEqual(gate.feed(body, undefined), [body]);
  assert.deepEqual(gate.finish(), []);
});
