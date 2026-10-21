/**
 * pinned-tls.mjs against local TLS servers in both certificate shapes:
 *
 *   - self-signed (the bring-up shape, where the old `ca: <leaf>` pin worked)
 *   - CA-issued leaf (the Let's Encrypt shape served since #196, where it did not)
 *
 * Run: node --test client/pinned-tls.test.mjs
 * (not the client/*.test.mjs glob: browser-verify.test.mjs talks to production.)
 *
 * Certificates are minted with the system openssl into a temp dir per run.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { MAX_RESPONSE_BYTES, connectPinned, fetchPeerCertDer, pinnedRequest } from './pinned-tls.mjs';

const dir = mkdtempSync(join(tmpdir(), 'pinned-tls-'));
const servers = [];

function openssl(...args) {
  return execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Self-signed cert for localhost. */
function mintSelfSigned(name) {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.crt`, '-days', '2', '-subj', `/CN=${name}`,
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1');
  return { key: readFileSync(join(dir, `${name}.key`)), cert: readFileSync(join(dir, `${name}.crt`)) };
}

/** A leaf issued by a throwaway CA, served WITH its intermediate like a real chain. */
function mintChained(name) {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', `${name}-ca.key`, '-out', `${name}-ca.crt`, '-days', '2', '-subj', `/CN=${name} test CA`,
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`);
  writeFileSync(join(dir, `${name}.ext`), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
  openssl('x509', '-req', '-in', `${name}.csr`, '-CA', `${name}-ca.crt`, '-CAkey', `${name}-ca.key`,
    '-CAcreateserial', '-out', `${name}.crt`, '-days', '2', '-extfile', `${name}.ext`);
  const leaf = readFileSync(join(dir, `${name}.crt`));
  const ca = readFileSync(join(dir, `${name}-ca.crt`));
  return { key: readFileSync(join(dir, `${name}.key`)), cert: Buffer.concat([leaf, ca]), leaf };
}

function serve({ key, cert }) {
  return new Promise((resolve) => {
    const srv = https.createServer({ key, cert }, (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ path: req.url, method: req.method }));
    });
    srv.listen(0, '127.0.0.1', () => {
      servers.push(srv);
      resolve({ srv, port: srv.address().port });
    });
  });
}

const leafDer = (pem) => Buffer.from(new X509Certificate(pem).raw);

let selfSigned, chained, selfPort, chainPort;
before(async () => {
  selfSigned = mintSelfSigned('self');
  chained = mintChained('leaf');
  selfPort = (await serve(selfSigned)).port;
  chainPort = (await serve(chained)).port;
});
after(() => {
  for (const s of servers) s.close();
  rmSync(dir, { recursive: true, force: true });
});

test('the old ca:<leaf> pin fails on a CA-issued leaf (the root cause)', async () => {
  const err = await new Promise((resolve) => {
    const req = https.request(
      { host: '127.0.0.1', port: chainPort, path: '/x', ca: chained.leaf, checkServerIdentity: () => undefined },
      () => resolve(null),
    );
    req.on('error', resolve);
    req.end();
  });
  assert.ok(err, 'expected the request to fail');
  // Production serves the Let's Encrypt chain without its root, so OpenSSL
  // reports "unable to get local issuer certificate" (what the verifier printed
  // against api.ppq.ai). This local chain carries its own root, so the same
  // defect surfaces as "self-signed certificate in certificate chain". Either
  // way: a non-self-signed leaf is never a trust anchor.
  assert.match(err.message, /unable to get local issuer certificate|self-signed certificate in certificate chain/);
});

test('fetchPeerCertDer returns the served leaf for both shapes', async () => {
  const a = await fetchPeerCertDer({ host: '127.0.0.1', port: selfPort });
  assert.ok(a.equals(leafDer(selfSigned.cert)));
  const b = await fetchPeerCertDer({ host: '127.0.0.1', port: chainPort });
  assert.ok(b.equals(leafDer(chained.leaf)));
});

test('pinnedRequest succeeds against a self-signed server when the pin matches', async () => {
  const res = await pinnedRequest(
    { host: '127.0.0.1', port: selfPort, expectedDer: leafDer(selfSigned.cert) },
    '/attestation?nonce=00',
  );
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { path: '/attestation?nonce=00', method: 'GET' });
});

test('pinnedRequest succeeds against a CA-issued chain when the pin matches', async () => {
  const res = await pinnedRequest(
    { host: '127.0.0.1', port: chainPort, expectedDer: leafDer(chained.leaf) },
    '/v1/chat/completions',
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
  );
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { path: '/v1/chat/completions', method: 'POST' });
});

test('pinnedRequest refuses, before sending, when the server presents a different certificate', async () => {
  let hit = 0;
  const srv = https.createServer({ key: chained.key, cert: chained.cert }, (req, res) => {
    hit++;
    res.end('leaked');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  servers.push(srv);
  await assert.rejects(
    pinnedRequest(
      { host: '127.0.0.1', port: srv.address().port, expectedDer: leafDer(selfSigned.cert) },
      '/attestation',
    ),
    /certificate pin mismatch/,
  );
  // Give a stray request a tick to land; none should.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(hit, 0, 'no application bytes may reach an unpinned server');
});

test('connectPinned resolves a connected socket that has sent nothing', async () => {
  const sock = await connectPinned({ host: '127.0.0.1', port: selfPort, expectedDer: leafDer(selfSigned.cert) });
  assert.equal(sock.bytesWritten, 0);
  assert.ok(sock.encrypted);
  sock.destroy();
});

// ── deadline, truncation, size bound (CodeRabbit review on #341) ──────────────
// The first pinned request goes to a server that has proved nothing yet, so
// the verifier must not hang on it, crash on it, or buffer it without limit.

/** A pinned-cert server whose handler is ours; returns its port. */
async function serveWith(handler) {
  const srv = https.createServer({ key: selfSigned.key, cert: selfSigned.cert }, handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  servers.push(srv);
  return srv.address().port;
}

test('pinnedRequest rejects when the pinned server never answers', async () => {
  const port = await serveWith(() => {
    /* accept the request, send nothing */
  });
  const t0 = Date.now();
  await assert.rejects(
    pinnedRequest({ host: '127.0.0.1', port, expectedDer: leafDer(selfSigned.cert), timeoutMs: 300 }, '/attestation'),
    /timed out after 300 ms/,
  );
  assert.ok(Date.now() - t0 < 5_000, 'the deadline must be the one we set, not a default');
});

test('pinnedRequest rejects, not crashes, when the response is truncated after its headers', async () => {
  const port = await serveWith((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '1000' });
    res.write('{"partial":');
    setTimeout(() => res.socket.destroy(), 20);
  });
  await assert.rejects(
    pinnedRequest({ host: '127.0.0.1', port, expectedDer: leafDer(selfSigned.cert) }, '/attestation'),
    (e) => e instanceof Error,
  );
});

test('pinnedRequest rejects a response larger than maxResponseBytes and stops reading', async () => {
  let written = 0;
  const port = await serveWith((req, res) => {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    const chunk = Buffer.alloc(64 * 1024, 0x41);
    const pump = () => {
      if (res.destroyed || res.socket?.destroyed) return;
      written += chunk.length;
      res.write(chunk, () => setImmediate(pump));
    };
    pump();
  });
  await assert.rejects(
    pinnedRequest(
      { host: '127.0.0.1', port, expectedDer: leafDer(selfSigned.cert), maxResponseBytes: 256 * 1024 },
      '/attestation',
    ),
    /exceeded 262144 bytes/,
  );
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(written < 64 * 1024 * 1024, 'the server must have been cut off, not drained');
});

test('MAX_RESPONSE_BYTES is the default bound and comfortably holds an attestation response', () => {
  assert.equal(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
});
