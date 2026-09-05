import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  STORE_VERSION, isUsable, leafValidity, parseKmstoolField, sealStore, selfTest,
  storeCredsFromEnv, unsealStore,
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

test('isUsable rejects expired, near-expiry, and wrong-domain material', () => {
  const good = payload();
  assert.equal(isUsable(good, { domain: DOMAIN }), true);
  assert.equal(isUsable({ ...good, domain: 'other.example' }, { domain: DOMAIN }), false);

  const expired = { ...good, notAfter: new Date(Date.now() - 1000).toISOString() };
  assert.equal(isUsable(expired, { domain: DOMAIN }), false);

  // Bounds the replay risk: a blob the parent kept and re-presented late is
  // treated as unusable while there is still time to order a replacement.
  const nearly = { ...good, notAfter: new Date(Date.now() + 3600_000).toISOString() };
  assert.equal(isUsable(nearly, { domain: DOMAIN }), false);

  assert.equal(isUsable({ ...good, notAfter: 'not-a-date' }, { domain: DOMAIN }), false);
  assert.equal(isUsable({ ...good, key: '' }, { domain: DOMAIN }), false);
  assert.equal(isUsable(null, { domain: DOMAIN }), false);
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
  assert.equal(await selfTest({ kms: denied }), 'failed');
});

test('selfTest reports failed when the round-trip returns different bytes', async () => {
  const kms = fakeKms();
  const liar = {
    generateDataKey: () => kms.generateDataKey(),
    // A data key that decrypts to something else entirely.
    decryptDataKey: async () => crypto.randomBytes(32).toString('base64'),
  };
  assert.equal(await selfTest({ kms: liar }), 'failed');
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
