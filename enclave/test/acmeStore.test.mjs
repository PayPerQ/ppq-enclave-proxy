import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import {
  RENEW_BEFORE_MS, STORE_VERSION, isServable, leafValidity, loadCachedCertificate,
  needsRenewal, parseKmstoolField, parseStoreBlob, sealStore, selfTest,
  SELF_TEST_REASONS, classifyFailure, credentialArgs, decryptArgs, genkeyArgs,
  saveSealedBlob, storeCredsFromEnv, unsealStore,
} from '../src/acmeStore.mjs';

// A stand-in for KMS. `genkey` hands back a key in the clear plus a "wrapped"
// copy; `decrypt` reverses it. The wrapping is deliberately trivial -- what is
// under test is this module's envelope handling, not KMS.
function fakeKms() {
  const issued = new Map();
  return {
    calls: { generate: 0, decrypt: 0 },
    async generateDataKey() {
      this.calls.generate += 1;
      const dek = crypto.randomBytes(32);
      const handle = `wrapped-${issued.size}`;
      issued.set(handle, dek);
      return { plaintextB64: dek.toString('base64'), ciphertextB64: handle };
    },
    async decryptDataKey(handle) {
      this.calls.decrypt += 1;
      const dek = issued.get(handle);
      if (!dek) throw new Error('AccessDeniedException: no such key');
      return dek.toString('base64');
    },
  };
}

const DOMAIN = 'enclave.ppq.ai';
const payload = () => ({
  domain: DOMAIN,
  cert: '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n',
  key: '-----BEGIN PRIVATE KEY-----\nkeymaterial\n-----END PRIVATE KEY-----\n',
  notAfter: new Date(Date.now() + 60 * 86_400_000).toISOString(),
});

test('a sealed store round-trips through unseal', async () => {
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  assert.equal(blob.v, STORE_VERSION);
  assert.equal(blob.domain, DOMAIN);
  const back = await unsealStore(blob, { kms });
  assert.equal(back.key, payload().key);
  assert.equal(back.cert, payload().cert);
});

test('the blob carries no plaintext key material', async () => {
  // The whole point: this lands on storage the parent owns.
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  const serialized = JSON.stringify(blob);
  assert.ok(!serialized.includes('keymaterial'), 'private key leaked into the blob');
  assert.ok(!serialized.includes('BEGIN PRIVATE KEY'), 'PEM header leaked into the blob');
  assert.ok(!serialized.includes('chain'), 'certificate leaked into the blob');
});

test('every seal uses a fresh data key and a fresh IV', async () => {
  const kms = fakeKms();
  const a = await sealStore(payload(), { kms });
  const b = await sealStore(payload(), { kms });
  assert.notEqual(a.wrappedDek, b.wrappedDek);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext, 'identical ciphertext means IV reuse');
});

test('editing the header breaks authentication rather than being ignored', async () => {
  // The domain is cleartext so an operator can identify the file, which means
  // it is also editable. It is bound as AAD precisely so that is detected.
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  await assert.rejects(
    () => unsealStore({ ...blob, domain: 'evil.example' }, { kms }),
    /unable to authenticate|unsupported state|bad decrypt/i,
  );
});

test('a tampered ciphertext is rejected', async () => {
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  const bytes = Buffer.from(blob.ciphertext, 'base64');
  bytes[0] ^= 0xff;
  await assert.rejects(
    () => unsealStore({ ...blob, ciphertext: bytes.toString('base64') }, { kms }),
    /unable to authenticate|unsupported state|bad decrypt/i,
  );
});

test('an unknown store version is refused, not best-effort parsed', async () => {
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  await assert.rejects(() => unsealStore({ ...blob, v: 99 }, { kms }), /unsupported store version/);
});

test('a malformed blob is refused before any KMS call is spent', async () => {
  const kms = fakeKms();
  await assert.rejects(() => unsealStore({ v: STORE_VERSION, alg: 'aes-256-gcm' }, { kms }), /missing/);
  assert.equal(kms.calls.decrypt, 0, 'called KMS for a blob that was already invalid');
});

test('a KMS refusal propagates rather than yielding a half-open store', async () => {
  // This is what a PCR0 that is not on the allow-list looks like from here.
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  const denied = { ...kms, async decryptDataKey() { throw new Error('AccessDeniedException'); } };
  await assert.rejects(() => unsealStore(blob, { kms: denied }), /AccessDeniedException/);
});

test('isServable rejects expired and wrong-domain material', () => {
  const good = payload();
  assert.equal(isServable(good, { domain: DOMAIN }), true);
  assert.equal(isServable({ ...good, domain: 'other.example' }, { domain: DOMAIN }), false);
  assert.equal(
    isServable({ ...good, notAfter: new Date(Date.now() - 1000).toISOString() }, { domain: DOMAIN }),
    false,
  );
  assert.equal(isServable({ ...good, notAfter: 'not-a-date' }, { domain: DOMAIN }), false);
  assert.equal(isServable({ ...good, key: '' }, { domain: DOMAIN }), false);
  assert.equal(isServable(null, { domain: DOMAIN }), false);
});

test('a certificate inside its renewal window is still SERVABLE', () => {
  // The split that keeps a failed renewal from dropping TLS: needing renewal
  // and being unusable are different questions.
  const soon = { ...payload(), notAfter: new Date(Date.now() + 5 * 86_400_000).toISOString() };
  assert.equal(isServable(soon, { domain: DOMAIN }), true);
  assert.equal(needsRenewal(soon), true);
});

test('needsRenewal tracks the window, and unparsable material orders', () => {
  const far = { notAfter: new Date(Date.now() + RENEW_BEFORE_MS + 86_400_000).toISOString() };
  assert.equal(needsRenewal(far), false);
  const near = { notAfter: new Date(Date.now() + RENEW_BEFORE_MS - 86_400_000).toISOString() };
  assert.equal(needsRenewal(near), true);
  assert.equal(needsRenewal({}), true);
  assert.equal(needsRenewal(null), true);
});

test('parseStoreBlob tolerates junk from the parent rather than throwing', () => {
  assert.equal(parseStoreBlob(''), null);
  assert.equal(parseStoreBlob(undefined), null);
  assert.equal(parseStoreBlob('not json'), null);
  assert.equal(parseStoreBlob('"a string"'), null);
  assert.deepEqual(parseStoreBlob('{"v":1}'), { v: 1 });
});

test('loadCachedCertificate returns a servable certificate and does not ask for an order', async () => {
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  const out = await loadCachedCertificate({ raw: JSON.stringify(blob), kms, domain: DOMAIN });
  assert.equal(out.servable, true);
  assert.equal(out.renew, false);
  assert.equal(out.payload.key, payload().key);
});

test('loadCachedCertificate asks for an order when the cache is absent', async () => {
  const kms = fakeKms();
  const out = await loadCachedCertificate({ raw: '', kms, domain: DOMAIN });
  assert.equal(out.payload, null);
  assert.equal(out.renew, true);
});

test('a cached certificate for the WRONG domain is not served', async () => {
  const kms = fakeKms();
  const blob = await sealStore({ ...payload(), domain: 'other.example' }, { kms, domain: 'other.example' });
  const out = await loadCachedCertificate({ raw: JSON.stringify(blob), kms, domain: DOMAIN });
  assert.equal(out.payload, null);
  assert.equal(out.renew, true);
});

test('a cached certificate inside its renewal window is served AND renewed', async () => {
  // Both must hold: serve immediately so the restart has TLS, and order a
  // replacement because expiry is close.
  const kms = fakeKms();
  const soon = { ...payload(), notAfter: new Date(Date.now() + 5 * 86_400_000).toISOString() };
  const blob = await sealStore(soon, { kms });
  const out = await loadCachedCertificate({ raw: JSON.stringify(blob), kms, domain: DOMAIN });
  assert.equal(out.servable, true, 'must still serve while renewing');
  assert.equal(out.renew, true, 'must order a replacement');
  assert.ok(out.payload);
});

test('an unsealable cache degrades to ordering instead of throwing', async () => {
  // What a PCR0 missing from the CMK allow-list looks like on a real boot: the
  // enclave must still come up and get itself a certificate.
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  const denied = { async decryptDataKey() { throw new Error('AccessDeniedException'); } };
  const out = await loadCachedCertificate({ raw: JSON.stringify(blob), kms: denied, domain: DOMAIN });
  assert.equal(out.payload, null);
  assert.equal(out.renew, true);
});

test('an unconfigured store never claims a cached certificate', async () => {
  const out = await loadCachedCertificate({ raw: '{"v":1}', kms: null, domain: DOMAIN });
  assert.equal(out.payload, null);
  assert.equal(out.renew, true);
});

test('parseKmstoolField reads the labelled line and rejects a missing one', () => {
  const out = 'CIPHERTEXT: AAAA\nPLAINTEXT: BBBB\n';
  assert.equal(parseKmstoolField(out, 'CIPHERTEXT'), 'AAAA');
  assert.equal(parseKmstoolField(out, 'PLAINTEXT'), 'BBBB');
  assert.throws(() => parseKmstoolField('nothing here', 'PLAINTEXT'), /no PLAINTEXT field/);
});

test('leafValidity reads the window off a real certificate', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.ok(privateKey && publicKey);
  // X509Certificate cannot be constructed from parts in Node, so this asserts
  // the failure direction that actually matters: junk must throw at seal time
  // rather than produce a store whose freshness can never be evaluated.
  assert.throws(() => leafValidity('-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n'));
});

test('selfTest reports absent when the store is unconfigured', async () => {
  // Absent is the shipped-inert state, not a failure: no CMK id in the init
  // blob means nothing here runs.
  assert.equal(await selfTest({ kms: null }), 'absent');
});

test('selfTest reports ok on a real round-trip', async () => {
  const kms = fakeKms();
  assert.equal(await selfTest({ kms }), 'ok');
  assert.equal(kms.calls.generate, 1);
  assert.equal(kms.calls.decrypt, 1);
});

test('selfTest reports failed on a KMS denial and does not throw', async () => {
  // This is what a PCR0 missing from the CMK allow-list looks like — the #11
  // failure. It must surface on /health, and it must not take the enclave down.
  const denied = {
    async generateDataKey() { throw new Error('AccessDeniedException'); },
    async decryptDataKey() { throw new Error('unreachable'); },
  };
  // The NAMED form wins over the generic one: it is more specific and the name
  // is on the allowed vocabulary.
  assert.equal(await selfTest({ kms: denied }), 'failed:kms-AccessDeniedException');
});

test('selfTest reports a KMS that returns the WRONG data key', async () => {
  // The tag fails to verify before any equality check can run, so this is
  // unseal-failed rather than roundtrip-mismatch. On a real boot it means the
  // stored blob and its wrapped key were separated, not a permissions problem.
  const kms = fakeKms();
  const liar = {
    generateDataKey: () => kms.generateDataKey(),
    decryptDataKey: async () => crypto.randomBytes(32).toString('base64'),
  };
  assert.equal(await selfTest({ kms: liar }), 'failed:unseal-failed');
});

test('storeCredsFromEnv needs a key id AND credentials, else null', () => {
  const full = {
    ACME_STORE_KEY_ID: 'cmk', KMS_AWS_ACCESS_KEY_ID: 'akid',
    KMS_AWS_SECRET_ACCESS_KEY: 'secret', KMS_AWS_SESSION_TOKEN: 'tok',
    KMS_REGION: 'us-east-1', KMS_PORT: '8000',
  };
  assert.equal(storeCredsFromEnv(full).keyId, 'cmk');
  assert.equal(storeCredsFromEnv({ ...full, ACME_STORE_KEY_ID: '' }), null);
  assert.equal(storeCredsFromEnv({ ...full, KMS_AWS_ACCESS_KEY_ID: '' }), null);
  assert.equal(storeCredsFromEnv({ ...full, KMS_AWS_SECRET_ACCESS_KEY: '' }), null);
  assert.equal(storeCredsFromEnv({}), null);
});

test('storeCredsFromEnv defaults region and proxy port rather than failing', () => {
  const creds = storeCredsFromEnv({
    ACME_STORE_KEY_ID: 'cmk', KMS_AWS_ACCESS_KEY_ID: 'akid',
    KMS_AWS_SECRET_ACCESS_KEY: 'secret',
  });
  assert.equal(creds.region, 'us-east-1');
  assert.equal(creds.proxyPort, '8000');
  assert.equal(creds.sessionToken, '');
});

test('saveSealedBlob delivers the blob and reports success', async () => {
  const received = [];
  const server = net.createServer((sock) => {
    const chunks = [];
    sock.on('data', (d) => chunks.push(d));
    // End-of-stream is end-of-object, which is why the client must end() the
    // socket rather than leave it open.
    sock.on('end', () => { received.push(Buffer.concat(chunks).toString()); sock.destroy(); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const kms = fakeKms();
    const blob = await sealStore(payload(), { kms });
    assert.equal(await saveSealedBlob(blob, { port }), true);
    // Give the server's 'end' handler a turn before asserting.
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(received.length, 1);
    const parsed = JSON.parse(received[0]);
    assert.equal(parsed.wrappedDek, blob.wrappedDek);
    assert.ok(!received[0].includes('keymaterial'), 'plaintext key crossed the save channel');
  } finally {
    server.close();
  }
});

test('saveSealedBlob resolves false rather than throwing when the parent is not listening', async () => {
  // Failing to persist a certificate we already hold must not stop us serving
  // it -- the cost is one order on the next boot, not an outage.
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  // Port 1 on loopback: reliably refused, no listener to race.
  assert.equal(await saveSealedBlob(blob, { port: 1, timeoutMs: 2000 }), false);
});

test('saveSealedBlob with no channel configured is a no-op, not an error', async () => {
  const kms = fakeKms();
  const blob = await sealStore(payload(), { kms });
  assert.equal(await saveSealedBlob(blob, { port: 0 }), false);
});

test('classifyFailure maps each failure onto the fixed vocabulary', () => {
  const c = (m) => classifyFailure(new Error(m));
  // A named exception is reported by name; the generic ACCESS_DENIED remains
  // the fallback for wording that carries no name (e.g. an IAM-style message).
  assert.equal(c('AccessDeniedException: ...'), 'kms-AccessDeniedException');
  assert.equal(c('User: arn:... is not authorized to perform: kms:GenerateDataKey'),
    SELF_TEST_REASONS.ACCESS_DENIED);
  assert.equal(c("spawn /usr/bin/kmstool_enclave_cli ENOENT"), SELF_TEST_REASONS.TOOL_MISSING);
  assert.equal(c('kmstool genkey timed out after 20000ms'), SELF_TEST_REASONS.TIMEOUT);
  assert.equal(c('kmstool output had no PLAINTEXT field'), SELF_TEST_REASONS.BAD_OUTPUT);
  assert.equal(c('expected a 32-byte data key, got 16'), SELF_TEST_REASONS.BAD_KEY_LENGTH);
  assert.equal(c('round-trip returned different bytes'), SELF_TEST_REASONS.ROUNDTRIP_MISMATCH);
  assert.equal(c('Unsupported state or unable to authenticate data'), SELF_TEST_REASONS.UNSEAL_FAILED);
  assert.equal(c('kmstool genkey exited 1 stderr=present: something'), 'tool-exit-1-present');
  assert.equal(c('kmstool genkey exited 134 stderr=empty: '), 'tool-exit-134-empty');
  // Without the shape at all (older wording), the generic reason still applies.
  assert.equal(c('kmstool genkey exited 1: something'), SELF_TEST_REASONS.TOOL_ERROR);
  assert.equal(c('something else entirely'), SELF_TEST_REASONS.UNKNOWN);
});

test('classifyFailure never returns the underlying message', () => {
  // The errorReport.mjs rule, kept uniform: a reason, never a provider string.
  const secret = 'AccessDenied while handling PROMPT-TEXT-THAT-MUST-NOT-LEAK';
  const reason = classifyFailure(new Error(secret));
  assert.ok(!reason.includes('PROMPT-TEXT'));
  assert.ok(Object.values(SELF_TEST_REASONS).includes(reason));
});

test('classifyFailure surfaces a named AWS exception verbatim', () => {
  // The most specific honest signal available: kmstool swallows the KMS body,
  // so when a name does survive into stderr it is worth reporting exactly.
  assert.equal(
    classifyFailure(new Error('kmstool genkey exited 1: AccessDeniedException: nope')),
    'kms-AccessDeniedException',
  );
  assert.equal(
    classifyFailure(new Error('ValidationException: 1 validation error detected')),
    'kms-ValidationException',
  );
});

test('classifyFailure surfaces the HTTP status when kmstool swallows the body', () => {
  // The usual case: kmstool prints only this line, and the code is what
  // separates "malformed request" (400) from "not authorized" (403).
  assert.equal(
    classifyFailure(new Error('kmstool genkey exited 1: Got non-200 answer from KMS: 400')),
    'kms-http-400',
  );
  assert.equal(
    classifyFailure(new Error('Got non-200 answer from KMS: 403')),
    'kms-http-403',
  );
});

test('an AWS error name outside the vocabulary is never echoed', () => {
  const e = new Error('kmstool genkey exited 1 stderr=present: TotallyMadeUpException: SECRET-PAYLOAD');
  const r = classifyFailure(e);
  assert.ok(!r.includes('SECRET-PAYLOAD'));
  assert.ok(!r.includes('TotallyMadeUp'));
  assert.equal(r, 'tool-exit-1-present');
});

test('a 200 that cannot be parsed is distinct from a non-200', () => {
  assert.equal(
    classifyFailure(new Error('Could not read response from KMS: 200')),
    SELF_TEST_REASONS.BAD_RESPONSE,
  );
});

test('SDK failure wording is recognised ahead of the generic exit code', () => {
  const c = (m) => classifyFailure(new Error(m));
  assert.equal(c('kmstool genkey exited 1 stderr=present: Could not generate data key'),
    'kms-sdk-genkey-failed');
  assert.equal(c('Assertion failed: req->key_id'), 'kms-sdk-assert');
});

test('the session-token flag is ALWAYS passed, even when empty', () => {
  // THE #83 BUG. kmstool requires --aws-session-token ("must be set", exit 1)
  // and then dereferences it unconditionally in init_kms_client, so omitting it
  // fails the argument check before any KMS call. boot.sh has always passed it
  // unconditionally; this helper diverged and every genkey died there -- which
  // is exactly why decrypt worked and genkey did not.
  const base = {
    region: 'us-east-1', proxyPort: '8000',
    accessKeyId: 'akid', secretAccessKey: 'secret',
  };
  const withToken = credentialArgs({ ...base, sessionToken: 'tok' });
  assert.ok(withToken.includes('--aws-session-token'));
  assert.equal(withToken[withToken.indexOf('--aws-session-token') + 1], 'tok');

  for (const empty of ['', undefined, null]) {
    const args = credentialArgs({ ...base, sessionToken: empty });
    assert.ok(
      args.includes('--aws-session-token'),
      `omitted the flag for ${JSON.stringify(empty)} — kmstool exits 1 on that`,
    );
    assert.equal(args[args.indexOf('--aws-session-token') + 1], '');
  }
});

test('credentialArgs passes region and proxy port through', () => {
  const args = credentialArgs({
    region: 'eu-west-1', proxyPort: 9000,
    accessKeyId: 'a', secretAccessKey: 'b', sessionToken: 'c',
  });
  assert.equal(args[args.indexOf('--region') + 1], 'eu-west-1');
  assert.equal(args[args.indexOf('--proxy-port') + 1], '9000');
});

// ── The kmstool invocation shape ─────────────────────────────────────────────
// Both #83 bugs were divergences from boot.sh's proven invocation, and neither
// was caught by a unit test, because the tests substituted the KMS backend and
// never looked at the command line. These assert the argv itself.

const CREDS = {
  keyId: 'cmk-1234', region: 'us-east-1', proxyPort: '8000',
  accessKeyId: 'akid', secretAccessKey: 'secret', sessionToken: 'tok',
};

test('genkey passes the key id and the AES-256 spec', () => {
  const a = genkeyArgs(CREDS);
  assert.equal(a[0], 'genkey');
  assert.equal(a[a.indexOf('--key-id') + 1], 'cmk-1234');
  // The literal kmstool compares against is hyphenated, even though the AWS API
  // field is AES_256. Getting this wrong is a silent usage exit.
  assert.equal(a[a.indexOf('--key-spec') + 1], 'AES-256');
});

test('decrypt does NOT pass --key-id, matching boot.sh', () => {
  // THE SECOND #83 BUG. kmstool forwards key_id and encryption_algorithm
  // straight to aws_kms_decrypt_blocking; supplying one without the other made
  // every unseal fail with "Could not decrypt ciphertext". boot.sh sends
  // neither, and boot.sh is what works in production.
  const a = decryptArgs(CREDS, 'Q0lQSEVS');
  assert.equal(a[0], 'decrypt');
  assert.ok(!a.includes('--key-id'), 'decrypt must not send --key-id');
  assert.ok(!a.includes('--encryption-algorithm'));
  assert.equal(a[a.indexOf('--ciphertext') + 1], 'Q0lQSEVS');
});

test('both calls always carry the session token', () => {
  // THE FIRST #83 BUG: kmstool exits 1 on a missing token, before any KMS call.
  for (const a of [genkeyArgs(CREDS), decryptArgs(CREDS, 'x')]) {
    assert.ok(a.includes('--aws-session-token'));
  }
  const noTok = { ...CREDS, sessionToken: '' };
  for (const a of [genkeyArgs(noTok), decryptArgs(noTok, 'x')]) {
    assert.ok(a.includes('--aws-session-token'), 'flag must be present even when empty');
  }
});

// ── SAN certificates (#52 phase 3) ──────────────────────────────────────────
// One certificate covering several names is ONE order. Two certificates would
// spend two of Let's Encrypt's five weekly duplicates, and the limit is scoped
// to the registered domain, so every name under ppq.ai shares it.

const SAN = () => ({
  domain: 'enclave.ppq.ai',
  domains: ['enclave.ppq.ai', 'enclave-direct.ppq.ai'],
  cert: '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n',
  key: '-----BEGIN PRIVATE KEY-----\nkeymaterial\n-----END PRIVATE KEY-----\n',
  notAfter: new Date(Date.now() + 60 * 86_400_000).toISOString(),
});

test('a SAN certificate is servable for every name it covers', () => {
  const p = SAN();
  assert.equal(isServable(p, { domain: 'enclave.ppq.ai' }), true);
  assert.equal(isServable(p, { domain: 'enclave-direct.ppq.ai' }), true);
  assert.equal(isServable(p, { domains: p.domains }), true);
});

test('a SAN certificate is NOT servable for a name it omits', () => {
  const p = SAN();
  assert.equal(isServable(p, { domain: 'other.ppq.ai' }), false);
  assert.equal(
    isServable(p, { domains: ['enclave.ppq.ai', 'never-issued.ppq.ai'] }),
    false,
    'must not accept a cert missing one of the names we intend to serve',
  );
});

test('a single-name cert is refused once a second name is added', () => {
  // The transition that matters: the stored shadow-only certificate must not be
  // accepted once production is added, or the enclave serves a certificate that
  // does not match the name the browser asked for.
  const shadowOnly = { ...SAN(), domain: 'enclave-direct.ppq.ai', domains: ['enclave-direct.ppq.ai'] };
  assert.equal(isServable(shadowOnly, { domain: 'enclave-direct.ppq.ai' }), true);
  assert.equal(
    isServable(shadowOnly, { domains: ['enclave.ppq.ai', 'enclave-direct.ppq.ai'] }),
    false,
    'stale single-name cert must trigger a new order, not be served',
  );
});

test('a legacy blob with only `domain` still works', () => {
  // Blobs sealed before SAN support carry no `domains` array.
  const legacy = { ...SAN(), domains: undefined };
  assert.equal(isServable(legacy, { domain: 'enclave.ppq.ai' }), true);
  assert.equal(isServable(legacy, { domain: 'enclave-direct.ppq.ai' }), false);
});
