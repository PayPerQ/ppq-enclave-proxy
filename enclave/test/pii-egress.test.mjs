// The PII detector is reached like every other upstream: a loopback port that a
// host-side vsock-proxy forwards to ONE pinned destination, with TLS validated
// against the real hostname from inside the enclave. These tests drive the real
// transport (upstreams.mjs createTunnelFetch) and the real detector adapter
// against a fake TLS detector, in a child process so the throwaway CA can be
// trusted through NODE_EXTRA_CA_CERTS exactly as the enclave trusts real CAs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import https from 'node:https';
import { HOSTED_DETECTOR_HOST } from '../src/pii/detector.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (f) => readFileSync(join(root, f), 'utf8');
const src = (f) => pathToFileURL(join(root, 'enclave', 'src', f)).href;

function haveOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; }
}

function makeCert(dir) {
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyPath, '-out', certPath], { stdio: 'pipe' });
  return { keyPath, certPath, key: readFileSync(keyPath), cert: readFileSync(certPath) };
}

/** Fake hosted filter: records every request; `mode` decides the answer. */
function fakeDetector(tls) {
  const seen = [];
  let mode = 'ok';
  const server = https.createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      seen.push({ method: req.method, url: req.url, host: req.headers.host, auth: req.headers.authorization, body });
      if (mode === 'hang') return; // never answers
      const start = body.text.indexOf('Jane Roe');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ detected_spans: start < 0 ? [] : [{ label: 'private_person', start, end: start + 8 }] }));
    });
  });
  return { server, seen, setMode: (m) => { mode = m; } };
}

/** Run the real transport + detector in a child that trusts the throwaway CA. */
function runDetect({ certPath, host, port, timeoutMs = 5000, texts }) {
  const script = `
    import { createTunnelFetch } from ${JSON.stringify(src('upstreams.mjs'))};
    import { createDetector } from ${JSON.stringify(src('pii/detector.mjs'))};
    const d = createDetector({
      kind: 'tinfoil-hosted', url: 'https://${host}/redact', apiKey: 'test-tinfoil-key',
      fetch: createTunnelFetch({ tunnels: { ${JSON.stringify(host)}: ${port} } }), timeoutMs: ${timeoutMs},
    });
    const t0 = Date.now();
    try {
      const r = await d.detect(${JSON.stringify(texts)});
      console.log(JSON.stringify({ ok: true, ...r, ms: Date.now() - t0 }));
    } catch (e) {
      console.log(JSON.stringify({ ok: false, reason: e.reason, ms: Date.now() - t0 }));
    }
    process.exit(0);
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('exit', () => { try { resolve(JSON.parse(out.trim().split('\n').pop())); } catch { reject(new Error(`child output: ${out}\n${err}`)); } });
  });
}

test('the detector is reached through its tunnel with TLS pinned to the real host', { skip: !haveOpenssl() && 'openssl not available' }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-egress-'));
  const tls = makeCert(dir);
  const fake = fakeDetector(tls);
  await new Promise((r) => fake.server.listen(0, '127.0.0.1', r));
  const port = fake.server.address().port;
  t.after(() => { fake.server.closeAllConnections?.(); fake.server.close(); rmSync(dir, { recursive: true, force: true }); });

  await t.test('a detect call lands on POST /redact with the bearer key and the real Host', async () => {
    const r = await runDetect({ certPath: tls.certPath, host: 'localhost', port, texts: ['Hi, I am Jane Roe.', 'no pii'] });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.calls, 1);
    assert.deepEqual(r.spans, [[{ start: 9, end: 17, cls: 'PERSON' }], []]);
    const req = fake.seen.at(-1);
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/redact');
    assert.equal(req.host, 'localhost');
    assert.equal(req.auth, 'Bearer test-tinfoil-key');
    assert.equal(req.body.text, 'Hi, I am Jane Roe.\n\nno pii');
  });

  await t.test('a tunnel that leads somewhere else fails the handshake and sends nothing', async () => {
    const before = fake.seen.length;
    // The certificate is for `localhost`; naming another host is what a parent
    // redirecting the tunnel looks like from in here.
    const r = await runDetect({ certPath: tls.certPath, host: 'pii-filter.example.com', port, texts: ['Jane Roe'] });
    assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: 'network' });
    assert.equal(fake.seen.length, before, 'no request body reached the wrong host');
  });

  await t.test('the timeout aborts the in-flight request instead of waiting on it', async () => {
    fake.setMode('hang');
    const r = await runDetect({ certPath: tls.certPath, host: 'localhost', port, timeoutMs: 300, texts: ['Jane Roe'] });
    fake.setMode('ok');
    assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: 'timeout' });
    assert.ok(r.ms < 3000, `returned after ${r.ms} ms`);
  });
});

test('the detector tunnel exists on both ends and names the measured host', () => {
  const boot = read('enclave/boot.sh');
  const port = boot.match(/^PII_DETECTOR_VSOCK_PORT=(\d+)$/m)?.[1];
  assert.ok(port, 'boot.sh defines PII_DETECTOR_VSOCK_PORT');
  assert.match(boot, /socat TCP4-LISTEN:\$\{PII_DETECTOR_VSOCK_PORT\},reuseaddr,fork,bind=127\.0\.0\.1 \\\n\s+VSOCK-CONNECT:\$\{HOST_CID\}:\$\{PII_DETECTOR_VSOCK_PORT\} &/);
  assert.match(boot, /^export PII_DETECTOR_PORT=\$\{PII_DETECTOR_VSOCK_PORT\}$/m);
  // The key is the KMS-gated Tinfoil key; the host is never parent-chosen.
  assert.doesNotMatch(boot, /pii_detector_host|PII_DETECTOR_HOST/);

  const host = read('scripts/run-host.sh');
  assert.ok(host.includes(`"${port} ${HOSTED_DETECTOR_HOST} \${VSOCK_WORKERS}"`), 'run-host.sh starts the proxy on the same port');
  assert.ok(host.includes(`  - {address: ${HOSTED_DETECTOR_HOST}, port: 443}`), 'the host is on the vsock-proxy allowlist');
});
