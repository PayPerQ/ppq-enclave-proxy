// The renewal client's --pin-spki, end to end against a self-signed stand-in
// for the authority: a wrong pin is refused before any request reaches the
// server; the right pin gets through the CA-less handshake and the client
// proceeds (here: until it reaches the ACME steps it cannot perform in a test).
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { spkiSha256Hex } from '../../scripts/lib/spki.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const script = join(root, 'scripts', 'renew-cert-dns01.mjs');
const haveOpenssl = (() => { try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; } catch { return false; } })();

test('--pin-spki: wrong pin refused before any request; right pin passes the self-signed handshake', { skip: !haveOpenssl && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'renew-pin-'));
  const hits = [];
  let server;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=ppq-enclave-proxy', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'pipe' });
    const cert = readFileSync(join(dir, 'c.pem'));
    const pin = spkiSha256Hex(new X509Certificate(cert).raw);
    server = https.createServer({ key: readFileSync(join(dir, 'k.pem')), cert }, (req, res) => {
      hits.push(req.url);
      res.setHeader('content-type', 'application/json');
      // A certificate with 100 days left and no --force: the client stops right
      // after /health ("no renewal needed"), so the right-pin run needs no network.
      if (req.url === '/health') return res.end(JSON.stringify({ status: 'ok', acme_renewal: { mode: 'dns01-ci', authority: true }, acme_certificates: { '127.0.0.1': { not_after: new Date(Date.now() + 100 * 86_400_000).toISOString() } } }));
      res.statusCode = 503; res.end('{}');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = String(server.address().port);
    // Asynchronous on purpose: the stand-in server lives in this process, so a
    // synchronous spawn would starve it of the event loop and the client would
    // hang until killed.
    const run = (extra) => new Promise((resolve) => {
      const c = spawn(process.execPath, [script, '--host', '127.0.0.1', '--port', port, '--directory', 'staging', ...extra],
        { env: { ...process.env, ACME_CI_TOKEN: 't', GODADDY_API_TOKEN: 'g' } });
      let stdout = ''; let stderr = '';
      c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
      const t = setTimeout(() => c.kill('SIGKILL'), 15_000);
      c.on('close', (status, signal) => { clearTimeout(t); resolve({ status, signal, stdout, stderr }); });
    });

    // No pin: the CA check refuses the self-signed stand-in, nothing reaches it.
    let r = await run([]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /self-signed|self signed|unable to verify/i);
    assert.equal(hits.length, 0, 'no request may reach the server without a pin');

    // Wrong pin: refused at the handshake, nothing reaches the server.
    r = await run(['--pin-spki', 'ab'.repeat(32)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /presented key .* accepted:/);
    assert.equal(hits.length, 0, 'no request may reach the server with a wrong pin');

    // Right pin: the handshake is accepted and the client talks to the server.
    r = await run(['--pin-spki', pin.toUpperCase()]);
    assert.ok(hits.includes('/health'), `expected /health to be requested, got ${JSON.stringify(hits)}`);
    assert.equal(r.status, 0, `right pin should end cleanly (no renewal due): ${r.stderr}${r.stdout}`);
    assert.doesNotMatch(r.stderr + r.stdout, /self-signed|--pin-spki is/);

  } finally {
    server?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
