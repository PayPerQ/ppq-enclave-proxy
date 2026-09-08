// The EHBP identity survives a round trip through the sealed store (#52
// scaling), and a restored identity is byte-for-byte the one the real `ehbp`
// client seals to. Also: a stored identity that is wrong in any way is refused
// rather than half-loaded, and the resolver falls back to a fresh key loudly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Identity } from 'ehbp';
import { EhbpRecipient, HPKE_SUITE_ID, HPKE_IDENTITY_VERSION } from '../src/ehbp-server.mjs';
import { resolveHpkeIdentity } from '../src/hpkeIdentity.mjs';

async function sealTo(pubHex, body) {
  const identity = await Identity.fromPublicKeyHex(pubHex);
  const { request } = await identity.encryptRequestWithContext(
    new Request('https://enclave.ppq.ai/v1/chat/completions', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    }),
  );
  return { encap: request.headers.get('Ehbp-Encapsulated-Key'), body: Buffer.from(await request.arrayBuffer()) };
}

test('toJSON/fromJSON round-trips to the same public key and still decrypts', async () => {
  const original = await EhbpRecipient.generate();
  const json = await original.toJSON();
  assert.equal(json.v, HPKE_IDENTITY_VERSION);
  assert.equal(json.suite, HPKE_SUITE_ID);
  assert.match(json.publicKey, /^[0-9a-f]{64}$/);
  assert.match(json.privateKey, /^[0-9a-f]{64}$/);

  // Through JSON text, exactly as the sealed store carries it.
  const restored = await EhbpRecipient.fromJSON(JSON.parse(JSON.stringify(json)));
  assert.equal(await restored.publicKeyHex(), await original.publicKeyHex());

  // A client that sealed to the ORIGINAL key is opened by the RESTORED one --
  // the property a restart (or a second box) depends on.
  const { encap, body } = await sealTo(await original.publicKeyHex(), '{"canary":"after-restart"}');
  const { plaintext } = await restored.openRequest(encap, body);
  assert.equal(plaintext.toString('utf8'), '{"canary":"after-restart"}');
});

test('fromJSON refuses anything it should not trust', async () => {
  const good = await (await EhbpRecipient.generate()).toJSON();
  const other = await (await EhbpRecipient.generate()).toJSON();
  const cases = [
    [null, /not an object/],
    [{ ...good, v: 2 }, /version/],
    [{ ...good, suite: 'something-else' }, /suite/],
    [{ ...good, privateKey: good.privateKey.slice(0, 62) }, /privateKey/],
    [{ ...good, publicKey: 'zz' + good.publicKey.slice(2) }, /publicKey/],
    // A public key that is not the private key's: the mismatch that would
    // otherwise surface as every browser request failing to decrypt.
    [{ ...good, publicKey: other.publicKey }, /does not match/],
  ];
  for (const [input, want] of cases) {
    await assert.rejects(() => EhbpRecipient.fromJSON(input), want, JSON.stringify(input)?.slice(0, 60));
  }
});

test('resolveHpkeIdentity prefers the store and reports the source', async () => {
  const stored = await (await EhbpRecipient.generate()).toJSON();
  const logs = [];
  const r = await resolveHpkeIdentity({ stored, log: (m) => logs.push(m) });
  assert.equal(r.source, 'store');
  assert.equal(await r.recipient.publicKeyHex(), stored.publicKey);
  assert.deepEqual(logs, [], 'a clean load says nothing');
});

test('resolveHpkeIdentity generates when the store holds nothing', async () => {
  const r = await resolveHpkeIdentity({ stored: null });
  assert.equal(r.source, 'generated');
  assert.match(await r.recipient.publicKeyHex(), /^[0-9a-f]{64}$/);
});

test('resolveHpkeIdentity REJECTS a corrupt stored identity: serves fresh, reports it, never claims the store', async () => {
  const logs = [];
  const r = await resolveHpkeIdentity({ stored: { v: 1, suite: HPKE_SUITE_ID, publicKey: 'nope' }, log: (m) => logs.push(m) });
  assert.equal(r.source, 'rejected', 'a present-but-invalid identity is not the same as a missing one');
  assert.match(r.reason, /publicKey/);
  assert.match(await r.recipient.publicKeyHex(), /^[0-9a-f]{64}$/, 'still serves on a fresh key');
  assert.equal(logs.length, 1);
  assert.match(logs[0], /REJECTED/);
  assert.match(logs[0], /leaving the store untouched/);
});

test('resolveHpkeIdentity treats only null/undefined as "missing"', async () => {
  assert.equal((await resolveHpkeIdentity({ stored: undefined })).source, 'generated');
  assert.equal((await resolveHpkeIdentity({})).source, 'generated');
  // An empty object is PRESENT and invalid, not missing.
  assert.equal((await resolveHpkeIdentity({ stored: {} })).source, 'rejected');
});
