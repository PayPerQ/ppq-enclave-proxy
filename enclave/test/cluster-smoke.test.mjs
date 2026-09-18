// A real 2-worker cluster of the actual server, outside the enclave: no ACME,
// no KMS, no upstreams -- just the property this whole change exists for:
// every worker answers on the shared port and every worker presents the SAME
// EHBP public key, the one the primary resolved once.
//
// Needs `openssl` for a throwaway self-signed certificate; skipped without it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { buildProxyV2 } from '../src/proxyProtocol.mjs';

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}
/** Like getJson, but the way nginx reaches the api port: a PROXY header, then TLS. */
function getJsonViaProxyHeader(port, path) {
  return new Promise((resolve, reject) => {
    const raw = net.connect(port, '127.0.0.1', () => {
      raw.write(buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445));
      // No agent: createConnection must hand back the TLS socket itself.
      const secure = tls.connect({ socket: raw, servername: 'localhost', rejectUnauthorized: false });
      const req = https.request({ createConnection: () => secure, path }, (res) => {
        let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; }); res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
      });
      req.on('error', reject); req.end();
    });
    raw.on('error', reject);
  });
}
function getJson(port, path) {
  return new Promise((resolve, reject) => {
    // A new connection per probe: cluster distributes CONNECTIONS round-robin,
    // and the default agent would keep one alive and pin every probe to a worker.
    const req = https.request({ host: '127.0.0.1', port, path, rejectUnauthorized: false, timeout: 5000, agent: false }, (res) => {
      let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; }); res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('timeout'))); req.end();
  });
}

test('two workers serve the shared port with one EHBP identity', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cluster-smoke-'));
  const key = join(dir, 'key.pem'); const cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { stdio: 'pipe' });
  const port = await freePort();
  const ppPort = await freePort();
  const child = spawn(process.execPath, [fileURLToPath(new URL('../src/server.mjs', import.meta.url))], {
    env: {
      ...process.env, ENCLAVE_WORKERS: '2', INBOUND_PORT: String(port), PP_PORT: String(ppPort), TLS_KEY_PATH: key, TLS_CERT_PATH: cert, SETTLE_HOST: 'settle.invalid',
      // CI-driven renewal on (#52 DNS-01): no KMS here, so the store is inert
      // and "wants renewal" -- which in dns01-ci mode must NOT place an order.
      ACME_DOMAIN: 'localhost', ACME_RENEWAL_MODE: 'dns01-ci', ACME_RENEWAL_AUTHORITY: '1', ACME_CI_TOKEN: 'smoke-token',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d; }); child.stderr.on('data', (d) => { logs += d; });
  try {
    // Wait for the primary to count both workers ready -- the readiness
    // message itself, not a port probe -- then probe BOTH listeners exactly
    // once. A worker may only report ready after its TLS and PROXY-protocol
    // listeners are bound, so neither probe is allowed a retry.
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline && !/cluster: worker \d listening \(2\/2\)/.test(logs)) {
      if (child.exitCode !== null) assert.fail(`server exited early with ${child.exitCode}\n${logs}`);
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.match(logs, /cluster: worker \d listening \(2\/2\)/, `workers not ready within 20s\n${logs}`);
    const health = await getJson(port, '/health');
    assert.equal(health.workers, 2, logs);
    const ppHealth = await getJsonViaProxyHeader(ppPort, '/health');
    assert.equal(ppHealth.proxy_protocol, true, 'the PROXY port answered on the first try after readiness');

    const workers = new Set(); const keys = new Set();
    for (let i = 0; i < 30 && workers.size < 2; i += 1) {
      const h = await getJson(port, '/health');
      workers.add(h.worker); keys.add(h.hpke_public_key);
      assert.equal(h.hpke_identity, 'generated', 'no store -> generated, and every worker must say so');
    }
    assert.equal(workers.size, 2, `expected both workers to answer; saw ${[...workers]}\n${logs}`);
    assert.equal(keys.size, 1, `every worker must present the same EHBP key; saw ${[...keys]}`);
    assert.match([...keys][0], /^[0-9a-f]{64}$/);
    assert.match(logs, /cluster: starting 2 workers/);
    assert.match(logs, /delegated to CI \(dns01-ci\), no in-enclave order/);
    assert.equal(health.acme_renewal?.mode, 'dns01-ci');
    assert.equal(health.acme_renewal?.authority, true);
    assert.equal(health.proxy_protocol, true, 'PP_PORT set -> /health says so');

    // The PROXY-protocol port is a second shared port every worker accepts on.
    // Frame the connection the way nginx would (header, then TLS) and confirm
    // the same server answers, from both workers.
    const ppWorkers = new Set();
    for (let i = 0; i < 30 && ppWorkers.size < 2; i += 1) {
      const h = await getJsonViaProxyHeader(ppPort, '/health');
      ppWorkers.add(h.worker);
      assert.equal(h.proxy_protocol, true);
    }
    assert.equal(ppWorkers.size, 2, `expected both workers on the PROXY port; saw ${[...ppWorkers]}\n${logs}`);
    // Every worker logged both of its listeners before the primary counted it
    // ready (the primary's line is written on receipt of MSG.LISTENING, which
    // workerMain sends only after both binds). Stdout and IPC are separate
    // channels, so line ORDER is not asserted -- presence is, and readiness
    // was already exercised above: the very first probes after "listening
    // (2/2)" appeared answered on BOTH ports without a retry.
    for (const id of [1, 2]) {
      assert.match(logs, new RegExp(`cluster: worker ${id} proxy-protocol listener on 127\\.0\\.0\\.1:${ppPort}`), logs);
      assert.match(logs, new RegExp(`cluster: worker ${id} listening \\(TLS\\) on 127\\.0\\.0\\.1:${port}`), logs);
      assert.match(logs, new RegExp(`cluster: worker ${id} listening \\(\\d+/2\\)`), logs);
    }

    // The CI routes: invisible without the token, and answered by the PRIMARY
    // whichever worker took the connection.
    const post = (path, headers, body) => new Promise((resolve, reject) => {
      const req = https.request({ host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false, agent: false, headers }, (res) => {
        let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, body: b }));
      });
      req.on('error', reject); req.end(body);
    });
    assert.equal((await post('/acme/csr', {})).status, 404, 'no token -> not found');
    assert.equal((await post('/acme/csr', { authorization: 'Bearer wrong' })).status, 404, 'wrong token -> not found');
    const csrs = [];
    for (let i = 0; i < 6; i += 1) {
      const r = await post('/acme/csr', { authorization: 'Bearer smoke-token' });
      assert.equal(r.status, 200, r.body);
      const j = JSON.parse(r.body);
      assert.deepEqual(j.domains, ['localhost']);
      assert.ok(Buffer.from(j.csr_der_b64, 'base64').length > 100);
      csrs.push(j.csr_der_b64);
    }
    // Idempotent while a renewal is in flight: the same CSR comes back, from
    // whichever worker, so CI retries and duplicate runs cannot replace the
    // key underneath an order already in progress.
    assert.equal(new Set(csrs).size, 1, 'one pending CSR, handed out again');
    const bad = await post('/acme/install', { authorization: 'Bearer smoke-token', 'content-type': 'application/json' }, JSON.stringify({ cert: 'garbage' }));
    assert.equal(bad.status, 400, bad.body);
    assert.match(bad.body, /PEM/);

    // Kill one worker. The primary must respawn it, and the replacement must
    // present the SAME identity -- state replay, not regeneration.
    const victim = await getJson(port, '/health');
    process.kill(victim.pid, 'SIGKILL');
    const seenAfter = new Set();
    const until = Date.now() + 15_000;
    while (Date.now() < until && !seenAfter.has(3)) {
      try {
        const h = await getJson(port, '/health');
        seenAfter.add(h.worker);
        assert.equal(h.hpke_public_key, [...keys][0], 'replacement must carry the same EHBP key');
      } catch { /* a probe can race the dead worker's socket */ }
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(seenAfter.has(3), `expected a respawned worker (id 3); saw ${[...seenAfter]}\n${logs}`);
    assert.match(logs, /cluster: worker \d exited \(SIGKILL\); respawning in 1000ms/);
  } finally {
    // A child that already died never fires 'exit' again; waiting on it would
    // hang the test and hide the real failure (its logs are in the assertions).
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      await exited;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
