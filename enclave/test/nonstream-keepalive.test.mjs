// #411: a caller that did not ask for a stream, served by a direct upstream.
//
// Before: the enclave forwarded the caller's non-streaming body, the direct
// provider's JSON answer carried no bytes until the generation was done, and
// the NLB dropped the silent flow at 350 s without telling the enclave. The
// generation ran to the end, the settle billed it from the provider's usage,
// and the client got "Remote end closed connection without response"
// (Chatwoot 2171, 2026-11-05: eight answers of 9-22 minutes, $10.76 for zero
// bytes). And nothing could cancel an upstream whose headers were pending: a
// client that hung up during that wait was noticed only when the enclave
// wrote, after the provider had billed the whole answer.
//
// Now: the direct upstream is asked for a stream, the client's connection
// carries whitespace while it generates, the assembled chat.completion goes
// out at the end, and a client that hangs up cancels the upstream at once —
// before its headers (nothing settles) or mid-generation (what was generated
// settles, as for any aborted stream).
//
// Drives the real server against a fake hp and a fake Fireworks (the shape of
// client-abort-billing.test.mjs) and asserts what the client and hp receive.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

const SLUG = 'moonshotai/kimi-k3';
const UPSTREAM_ID = 'accounts/fireworks/models/kimi-k3';
const KEEPALIVE_MS = 60;

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
function listen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
}
function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
  });
}

/** Fake horse-power: a Fireworks candidate ahead of OpenRouter; records settles and reports. */
function fakeHp({ key, cert }) {
  const settles = [];
  const errors = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        authorized: true, credit_id: 'credit-under-test', api_key_id: null,
        resolved_model: body.model, is_free: false, web_search: false,
        upstreams: [
          { provider: 'fireworks', api_style: 'openai', host: 'api.fireworks.ai', path: '/inference/v1/chat/completions', key_ref: 'fireworks',
            upstream_model: UPSTREAM_ID, or_slug: SLUG, supports_tools: true, supports_image_input: false, context_length: 131072, tier: 'default' },
          { provider: 'openrouter', api_style: 'openai', host: 'openrouter.ai', path: '/api/v1/chat/completions', key_ref: 'openrouter', upstream_model: SLUG },
        ],
      }));
    }
    if (req.url === '/enclave/settle') { settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, settles, errors };
}

const sse = (ev) => `data: ${JSON.stringify(ev)}\n\n`;
const delta = (d, finish = null) => ({
  id: 'fw-1', object: 'chat.completion.chunk', created: 1793850000, model: UPSTREAM_ID,
  choices: [{ index: 0, delta: d, finish_reason: finish }],
});
const USAGE_FRAME = { id: 'fw-1', object: 'chat.completion.chunk', model: UPSTREAM_ID, choices: [], usage: { prompt_tokens: 11, completion_tokens: 2, total_tokens: 13 } };

/**
 * Fake Fireworks on the chat surface. `slow`: streams "Hel", pauses for several
 * keepalive periods, then the rest. `hold-headers`: reads the request and never
 * answers (the generation is running). `hold-after-delta`: headers and one
 * delta, then holds. Every mode records the request and whether the enclave
 * closed the socket.
 */
function fakeFireworks({ key, cert }) {
  const state = { mode: 'slow', seen: [], cancelled: 0, pauseMs: KEEPALIVE_MS * 8 };
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readJson(req);
    state.seen.push({ path: req.url, body, streaming: body.stream === true });
    if (req.url !== '/inference/v1/chat/completions') { res.writeHead(404); return res.end(); }
    // A held request ends only when the enclave destroys the socket: that is
    // the cancellation counted. (The enclave reuses one keep-alive socket for
    // consecutive requests, so a per-request socket listener would also fire
    // for every earlier, finished request on it.)
    const held = () => req.socket.once('close', () => { state.cancelled += 1; });
    if (state.mode === 'hold-headers') return held(); // no headers until then
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    if (state.mode === 'slow-headers') {
      // Headers now, the first frame only after a pause: a long prefill.
      res.flushHeaders();
      await new Promise((r) => setTimeout(r, state.pauseMs));
      if (res.destroyed) return;
    }
    if (state.mode === 'error-only') {
      // An error frame and nothing else: no completion to assemble.
      res.write(sse({ error: { message: 'boom', code: 500 } }));
      return res.end();
    }
    res.write(sse(delta({ role: 'assistant', content: 'Hel' })));
    if (state.mode === 'hold-after-delta') return held();
    if (state.mode === 'die-early') {
      // The socket dies right after the first delta, well inside the first
      // keepalive period (the delta must reach the enclave first).
      setTimeout(() => res.destroy(), 5);
      return;
    }
    if (state.mode !== 'slow-headers') await new Promise((r) => setTimeout(r, state.pauseMs));
    if (res.destroyed) return;
    if (state.mode === 'die-late') return res.destroy(); // after several keepalives
    res.write(sse(delta({ content: 'lo' })));
    res.write(sse(delta({}, 'stop')));
    res.write(sse(USAGE_FRAME));
    res.write('data: [DONE]\n\n');
    res.end();
  });
  return { server, state };
}

const NONSTREAM_BODY = JSON.stringify({
  model: SLUG,
  messages: [{ role: 'user', content: 'Write a long essay; take your time.' }],
});
const STREAM_BODY = JSON.stringify({
  model: SLUG, stream: true,
  messages: [{ role: 'user', content: 'Write a long essay; take your time.' }],
});

/** Send a request; `onHeaders` gets the response once its headers arrive. */
function start(port, body, requestId, onHeaders = () => {}) {
  const r = https.request({
    host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', rejectUnauthorized: false, agent: false,
    headers: {
      'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
      'x-credit-id': '00000000-0000-4000-8000-000000000001',
      'x-query-source': 'api', 'x-request-id': requestId,
    },
  }, onHeaders);
  r.on('error', () => {}); // our own destroy
  r.end(body);
  return r;
}

/** Send a request and collect every response chunk with the time it arrived. */
function collect(port, body, requestId) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    start(port, body, requestId, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push({ at: Date.now() - t0, text: c.toString('utf8') }));
      res.on('end', () => resolve({ res, chunks, text: chunks.map((c) => c.text).join('') }));
    });
  });
}

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for ${what}`);
}

test('a non-streaming caller on a direct route is kept alive, gets one chat.completion, and can cancel the upstream', { skip: !haveOpenssl() && 'openssl not available', timeout: 90_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nonstream-keepalive-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.fireworks.ai',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tlsPair = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, fwPort, orPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const hp = fakeHp(tlsPair);
  const fw = fakeFireworks(tlsPair);
  // OpenRouter must never be asked: a Fireworks candidate serves every case.
  let orAsked = 0;
  const or = https.createServer(tlsPair, (req, res) => { orAsked += 1; res.writeHead(500); res.end(); });
  await Promise.all([listen(hp.server, hpPort), listen(fw.server, fwPort), listen(or, orPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', HP_HOST_ALLOW: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      FIREWORKS_PORT: String(fwPort), FIREWORKS_API_KEY: 'fireworks-test-key',
      OPENROUTER_API_KEY: 'or-test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      NONSTREAM_KEEPALIVE_MS: String(KEEPALIVE_MS),
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // 1. The slow answer: whitespace keeps the connection alive, the body is
    //    one chat.completion, and the settle is the usage frame's.
    fw.state.mode = 'slow';
    const slow = await collect(inboundPort, NONSTREAM_BODY, 'req-nonstream-slow');
    assert.equal(slow.res.statusCode, 200, `status ${slow.res.statusCode}: ${slow.text}\n${logs}`);
    assert.match(String(slow.res.headers['content-type']), /application\/json/);
    assert.equal(fw.state.seen.length, 1, 'one upstream request');
    assert.equal(fw.state.seen[0].streaming, true, 'the upstream was asked for a stream');
    assert.equal(fw.state.seen[0].body.stream_options?.include_usage, true, 'with the usage frame pinned on');
    const whitespaceChunks = slow.chunks.filter((c) => /^\s+$/.test(c.text));
    assert.ok(whitespaceChunks.length >= 2, `keepalives arrived while the answer generated: ${JSON.stringify(slow.chunks.map((c) => [c.at, c.text.length]))}`);
    const bodyIndex = slow.chunks.findIndex((c) => c.text.includes('{'));
    assert.ok(whitespaceChunks[0].at < slow.chunks[bodyIndex].at, 'a keepalive came before the body');
    const answer = JSON.parse(slow.text);
    assert.equal(answer.object, 'chat.completion');
    assert.equal(answer.model, SLUG, 'the public slug, not the wire id');
    assert.equal(answer.choices[0].message.content, 'Hello');
    assert.equal(answer.choices[0].finish_reason, 'stop');
    assert.deepEqual(answer.usage, { prompt_tokens: 11, completion_tokens: 2, total_tokens: 13 });
    assert.ok(slow.res.headers['ppq-routing-receipt'], 'the routing receipt rides the headers of a JSON answer');
    const settled = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-nonstream-slow'), `the settle\n${logs}`);
    assert.equal(settled.provider, 'fireworks');
    assert.equal(settled.usage_source, 'upstream');
    assert.equal(settled.input_tokens, 11);
    assert.equal(settled.output_tokens, 2);
    assert.equal(settled.trace?.streaming, false, 'traced as the non-streaming call it was');
    assert.equal(settled.trace?.stream_end, 'clean');
    assert.equal(settled.trace?.bytes_out, Buffer.byteLength(JSON.stringify(answer)), 'keepalives are not answer bytes');
    assert.ok(settled.trace?.t_first_token_ms !== null && settled.trace?.t_first_token_ms !== undefined, 'the first token is on the trace');

    // 2. A streaming caller is served exactly as before.
    const streamed = await collect(inboundPort, STREAM_BODY, 'req-stream');
    assert.equal(streamed.res.statusCode, 200);
    assert.match(String(streamed.res.headers['content-type']), /text\/event-stream/);
    assert.match(streamed.text, /data: \[DONE\]/);
    assert.equal(streamed.chunks.filter((c) => /^\s+$/.test(c.text)).length, 0, 'no keepalives on a stream');
    const streamedSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-stream'), `the stream settle\n${logs}`);
    assert.equal(streamedSettle.trace?.streaming, true);

    // 3. Gone while the upstream's headers are pending: the request in flight
    //    is cancelled, nothing settles, the terminal report says client_abort.
    fw.state.mode = 'hold-headers';
    const seenBefore = fw.state.seen.length;
    const cancelledBefore = fw.state.cancelled;
    const pending = start(inboundPort, NONSTREAM_BODY, 'req-gone-before-headers');
    await waitFor(() => fw.state.seen.length === seenBefore + 1, `the upstream to receive the request\n${logs}`);
    pending.destroy();
    await waitFor(() => fw.state.cancelled === cancelledBefore + 1, `the upstream request to be cancelled\n${logs}`, 5_000);
    const abandoned = await waitFor(
      () => hp.errors.find((e) => e.trace?.client_request_id === 'req-gone-before-headers'),
      `the client_abort report\n${logs}`,
    );
    assert.equal(abandoned.code, 'client_abort');
    assert.equal(abandoned.terminal, true);
    assert.equal(abandoned.provider, 'fireworks', 'names the candidate that was in flight');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hp.settles.some((s) => s.request_id === 'req-gone-before-headers'), false, 'nothing was served, nothing settles');

    // 4. Gone mid-generation: the flow is alive (keepalives), so the close is
    //    seen at once, the upstream is cancelled, and what was generated
    //    settles from the enclave's own count — not the whole generation.
    fw.state.mode = 'hold-after-delta';
    const cancelledBeforeMid = fw.state.cancelled;
    const mid = start(inboundPort, NONSTREAM_BODY, 'req-gone-mid-generation', (res) => {
      // The first keepalive proves the headers are out and the body pending.
      res.once('data', () => mid.destroy());
    });
    await waitFor(() => fw.state.cancelled === cancelledBeforeMid + 1, `the mid-generation upstream to be cancelled\n${logs}`, 5_000);
    const midSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-gone-mid-generation'), `the mid-generation settle\n${logs}`);
    assert.equal(midSettle.trace?.stream_end, 'client_abort');
    assert.equal(midSettle.usage_source, 'counted');
    assert.ok(midSettle.output_tokens >= 1 && midSettle.output_tokens <= 3, `the one delta generated, not a whole answer: ${midSettle.output_tokens}`);

    // 5. The upstream dies BEFORE the first keepalive: the status line was
    //    still the enclave's to choose, so the caller gets a 502 with the
    //    error envelope — never a 200 carrying a partial object.
    fw.state.mode = 'die-early';
    const early = await collect(inboundPort, NONSTREAM_BODY, 'req-die-early');
    assert.equal(early.res.statusCode, 502, `status ${early.res.statusCode}: ${early.text}\n${logs}`);
    assert.match(String(early.res.headers['content-type']), /application\/json/);
    assert.equal(JSON.parse(early.text).error?.code, 502, early.text);
    assert.equal(JSON.parse(early.text).choices, undefined);
    const earlySettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-die-early'), `the die-early settle\n${logs}`);
    assert.equal(earlySettle.trace?.stream_end, 'upstream_error');
    assert.equal(earlySettle.failure_code, 'stream_failed');

    // 6. The upstream dies AFTER keepalives have gone out: the 200 is on the
    //    wire (a status cannot follow a byte), the body is the error envelope
    //    — the stream's in-band rule — and the row is a failure, never clean.
    fw.state.mode = 'die-late';
    const late = await collect(inboundPort, NONSTREAM_BODY, 'req-die-late');
    assert.equal(late.res.statusCode, 200, `status ${late.res.statusCode}: ${late.text}\n${logs}`);
    assert.ok(late.chunks.filter((c) => /^\s+$/.test(c.text)).length >= 2, `keepalives preceded the failure: ${JSON.stringify(late.chunks.map((c) => [c.at, c.text.length]))}`);
    assert.equal(JSON.parse(late.text).error?.code, 502, late.text);
    const lateSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-die-late'), `the die-late settle\n${logs}`);
    assert.equal(lateSettle.trace?.stream_end, 'upstream_error');
    assert.equal(lateSettle.failure_code, 'stream_failed');

    // 7. A stream that is only an error frame: nothing to assemble, the
    //    status is still ours, so it is a 502 carrying the upstream's error
    //    and the report says why.
    fw.state.mode = 'error-only';
    const errOnly = await collect(inboundPort, NONSTREAM_BODY, 'req-error-only');
    assert.equal(errOnly.res.statusCode, 502, `status ${errOnly.res.statusCode}: ${errOnly.text}\n${logs}`);
    assert.equal(JSON.parse(errOnly.text).error?.message, 'boom', errOnly.text);
    const errSettle = await waitFor(() => hp.settles.find((s) => s.request_id === 'req-error-only'), `the error-only settle\n${logs}`);
    assert.equal(errSettle.trace?.stream_end, 'upstream_error');
    assert.equal(errSettle.failure_code, 'stream_failed');
    const errReport = await waitFor(
      () => hp.errors.find((e) => e.trace?.client_request_id === 'req-error-only' && e.code === 'stream_failed'),
      `the stream_failed report\n${logs}`,
    );
    assert.equal(errReport.reason, 'ASSEMBLE_NO_COMPLETION', 'the reason reaches hp in the shape the sink forwards');

    // 8. A STREAMING caller gets the status line when the upstream's headers
    //    arrive, not with the first frame: Node holds a written head until the
    //    first body write unless it is flushed, and a long prefill is seconds.
    fw.state.mode = 'slow-headers';
    const t0 = Date.now();
    let headersAt = null;
    let firstFrameAt = null;
    await new Promise((resolve) => {
      start(inboundPort, STREAM_BODY, 'req-slow-headers', (res) => {
        headersAt = Date.now() - t0;
        res.once('data', () => { firstFrameAt = Date.now() - t0; });
        res.on('end', resolve);
      });
    });
    assert.ok(headersAt !== null && firstFrameAt !== null, `headers at ${headersAt} ms, first frame at ${firstFrameAt} ms`);
    assert.ok(firstFrameAt - headersAt >= fw.state.pauseMs / 2, `the status line waited for the first frame: headers at ${headersAt} ms, first frame at ${firstFrameAt} ms, pause ${fw.state.pauseMs} ms`);

    assert.equal(orAsked, 0, 'OpenRouter was never asked');
  } finally {
    child.kill('SIGKILL');
    await Promise.all([
      new Promise((r) => hp.server.close(r)),
      new Promise((r) => fw.server.close(r)),
      new Promise((r) => or.close(r)),
    ]);
    rmSync(dir, { recursive: true, force: true });
  }
});
