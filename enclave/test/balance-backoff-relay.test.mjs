// hp #1022: horse-power answers an account past its hourly balance-refusal
// threshold with 429 + Retry-After and the body code `balance_backoff`. The
// enclave must (1) relay the header, since SDKs slow down only when they see
// it; (2) remember the refusal per presented credential for exactly hp's
// window and answer repeats itself, without a round trip; (3) report none of
// it to /enclave/error — a backoff is the system working as designed, and
// one script's repeats are what buried real failures.
//
// Drives the real server against a fake hp because every one of those claims
// is about what crosses the wire to hp, which a unit test cannot show.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
const listen = (server, port) => new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const BACKOFF_BODY = {
  error: 'Insufficient credit on credit id 1d879f5e…. Please top up. Requests on this account were refused for insufficient balance 51 times in the past hour, so it is rate limited: retry after topping up, or no sooner than 2 seconds.',
  code: 'balance_backoff',
  retry_after_seconds: 2,
};
const RATE_LIMIT_BODY = {
  error: { message: 'Rate limit exceeded', type: 'rate_limit_error', code: 'credential_rate_limit', status: 429 },
};

/**
 * Fake horse-power. `mode` decides what /enclave/authorize answers:
 * 'ok' | 'balance_402' | 'backoff_429' | 'ratelimit_429'. Counts authorize
 * calls and keeps every error report.
 */
function fakeHp(tls) {
  const state = { mode: 'ok', authorizes: 0, errors: [], settles: [] };
  const server = https.createServer(tls, async (req, res) => {
    const body = await readJson(req);
    if (req.url === '/enclave/authorize') {
      state.authorizes += 1;
      switch (state.mode) {
        case 'balance_402':
          res.writeHead(402, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Insufficient credit on credit id 1d879f5e…. Please top up.' }));
        case 'backoff_429':
          res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '2' });
          return res.end(JSON.stringify(BACKOFF_BODY));
        case 'ratelimit_429':
          res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '7' });
          return res.end(JSON.stringify(RATE_LIMIT_BODY));
        default:
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({
            authorized: true, credit_id: 'credit-under-test', api_key_id: null,
            resolved_model: body.model, is_free: false, upstreams: [{ provider: 'openrouter' }],
          }));
      }
    }
    if (req.url === '/enclave/settle') { state.settles.push(body); res.writeHead(200); return res.end('{}'); }
    if (req.url === '/enclave/error') { state.errors.push(body); res.writeHead(204); return res.end(); }
    res.writeHead(404); res.end();
  });
  return { server, state };
}

function fakeOpenRouter(tls) {
  const state = { calls: 0 };
  const server = https.createServer(tls, async (req, res) => {
    await readJson(req);
    state.calls += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      id: 'gen-1', object: 'chat.completion', model: 'openai/gpt-4.1-mini',
      choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'served' } }],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    }));
  });
  return { server, state };
}

const ZOMBIE = '1d879f5e-7981-49b6-8a98-e4a41233f8c7';
const OTHER = 'fd9b4a01-3ab7-4ddf-b9f6-0bff6f05fe4f';

function chat(port, creditId, path = '/v1/chat/completions', body = { model: 'openai/gpt-4.1-mini', messages: [{ role: 'user', content: 'hi' }] }) {
  const payload = JSON.stringify({ stream: false, max_tokens: 16, ...body });
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-credit-id': creditId, 'x-query-source': 'api',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    r.end(payload);
  });
}

async function waitFor(predicate, what, ms = 15_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await sleep(50);
  }
  assert.fail(`timed out waiting for ${what}`);
}

test('hp’s balance backoff is relayed with Retry-After, remembered for its window, and never reported', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'balance-backoff-relay-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) };

  const [inboundPort, hpPort, orPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const hp = fakeHp(tls);
  const or = fakeOpenRouter(tls);
  await Promise.all([listen(hp.server, hpPort), listen(or.server, orPort)]);

  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      ENCLAVE_WORKERS: '1', INBOUND_PORT: String(inboundPort),
      TLS_KEY_PATH: keyPath, TLS_CERT_PATH: certPath,
      SETTLE_HOST: 'localhost', SETTLE_PORT: String(hpPort),
      OPENROUTER_HOST: 'localhost', OR_PORT: String(orPort),
      OPENROUTER_API_KEY: 'test-key', ENCLAVE_SETTLE_SECRET: 'test-secret',
      // count_tokens needs an Anthropic upstream configured or it answers 503
      // before authorize; the fake OpenRouter stands in (what it answers is
      // irrelevant — the assertion is that hp was asked).
      ANTHROPIC_HOST: 'localhost', ANTHROPIC_PORT: String(orPort), ANTHROPIC_API_KEY: 'anthropic-test-key',
      NODE_EXTRA_CA_CERTS: certPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; });
  child.stderr.on('data', (d) => { logs += d; });

  try {
    await waitFor(() => /listening \(TLS\)/.test(logs) || /worker \d listening/.test(logs), `the server to listen\n${logs}`);

    // Control: a plain balance 402 is relayed as before — reported, no header.
    hp.state.mode = 'balance_402';
    const plain = await chat(inboundPort, ZOMBIE);
    assert.equal(plain.status, 402, plain.text);
    assert.equal(plain.headers['retry-after'], undefined);
    assert.match(plain.json.error, /Insufficient credit/);
    await waitFor(() => hp.state.errors.length === 1, `the 402 to be reported\n${logs}`);
    assert.equal(hp.state.errors[0].code, 'authorize_rejected');
    assert.equal(hp.state.errors[0].upstream_status, 402);
    assert.equal(hp.state.authorizes, 1);

    // hp puts the account in backoff: the 429, the header and the body reach
    // the client, and nothing is reported.
    hp.state.mode = 'backoff_429';
    const first = await chat(inboundPort, ZOMBIE);
    assert.equal(first.status, 429, first.text);
    assert.equal(first.headers['retry-after'], '2');
    assert.deepEqual(first.json, BACKOFF_BODY);
    assert.equal(hp.state.authorizes, 2);

    // Repeats inside hp's window are answered by the enclave: hp is not asked.
    hp.state.mode = 'ok'; // if hp WERE asked, it would now serve — proving the answer was local
    const second = await chat(inboundPort, ZOMBIE);
    assert.equal(second.status, 429, second.text);
    assert.deepEqual(second.json, BACKOFF_BODY);
    assert.ok(['1', '2'].includes(second.headers['retry-after']), `seconds left, never 0: ${second.headers['retry-after']}`);
    const third = await chat(inboundPort, ZOMBIE);
    assert.equal(third.status, 429);
    assert.equal(hp.state.authorizes, 2, 'no authorize round trip for a held credential');
    assert.equal(or.state.calls, 0);

    // The Anthropic dialect is the same account and the same answer.
    const viaMessages = await chat(inboundPort, ZOMBIE, '/v1/messages', {
      model: 'anthropic/claude-haiku-4.5', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }],
    });
    assert.equal(viaMessages.status, 429, viaMessages.text);
    assert.ok(['1', '2'].includes(viaMessages.headers['retry-after']));
    assert.equal(viaMessages.json.type, 'error');
    assert.equal(hp.state.authorizes, 2);

    // Another credential is unaffected and is served.
    const other = await chat(inboundPort, OTHER);
    assert.equal(other.status, 200, other.text);
    assert.equal(other.json.choices[0].message.content, 'served');
    assert.equal(hp.state.authorizes, 3);

    // count_tokens spends nothing and hp authorizes it without a balance
    // gate, so a held credential still reaches hp there (Codex finding).
    const counted = await chat(inboundPort, ZOMBIE, '/v1/messages/count_tokens', {
      model: 'anthropic/claude-haiku-4.5', messages: [{ role: 'user', content: 'hi' }],
    });
    assert.notEqual(counted.status, 429, `count_tokens must not be backed off locally: ${counted.text}`);
    assert.equal(hp.state.authorizes, 4, `count_tokens asked hp (got ${counted.status}: ${counted.text})`);

    // Past hp's window the enclave asks again; hp (topped up) serves.
    await sleep(2_100);
    const afterWindow = await chat(inboundPort, ZOMBIE);
    assert.equal(afterWindow.status, 200, afterWindow.text);
    assert.equal(hp.state.authorizes, 5);

    // The credential-rate-limit 429 relays its header but is NOT remembered:
    // the next request still reaches hp.
    hp.state.mode = 'ratelimit_429';
    const limited = await chat(inboundPort, ZOMBIE);
    assert.equal(limited.status, 429, limited.text);
    assert.equal(limited.headers['retry-after'], '7');
    assert.equal(limited.json.error.code, 'credential_rate_limit');
    assert.equal(hp.state.authorizes, 6);
    hp.state.mode = 'ok';
    const again = await chat(inboundPort, ZOMBIE);
    assert.equal(again.status, 200, again.text);
    assert.equal(hp.state.authorizes, 7);

    // Throughout: exactly one error report, the control 402. The rate-limit
    // 429 is reported too (it is a real refusal hp made), so allow it.
    await sleep(200);
    const codes = hp.state.errors.map((e) => `${e.code}:${e.upstream_status}`);
    assert.deepEqual(codes, ['authorize_rejected:402', 'authorize_rejected:429'], `backoff refusals are never reported: ${codes}`);
  } finally {
    child.kill('SIGKILL');
    for (const s of [hp.server, or.server]) s.closeAllConnections?.();
    await Promise.all([hp.server, or.server].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  }
});
