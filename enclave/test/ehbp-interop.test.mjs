/**
 * Interop test: the real `ehbp` browser client <-> our EhbpRecipient.
 * Proves the enclave's recipient decrypts what the client encrypts, and the
 * client decrypts what the recipient encrypts — byte-for-byte over the EHBP
 * wire format. No enclave/network needed.
 *
 *   node test/ehbp-interop.test.mjs
 */
import assert from 'node:assert';
import { Identity } from 'ehbp';
import { EhbpRecipient } from '../src/ehbp-server.mjs';

const REQUEST_BODY = JSON.stringify({
  model: 'openai/gpt-4o-mini',
  messages: [{ role: 'user', content: 'SECRET-INTEROP-CANARY-42' }],
  stream: true,
});
const RESPONSE_CHUNKS = [
  'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n',
  'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n',
  'data: [DONE]\n\n',
];

function frames(...bufs) {
  return Buffer.concat(bufs);
}

async function main() {
  // 1. Enclave side generates its HPKE keypair; publishes the public key (this
  //    is what the attestation will commit to).
  const recipient = await EhbpRecipient.generate();
  const pubHex = await recipient.publicKeyHex();
  assert.strictEqual(pubHex.length, 64, 'X25519 pubkey should be 32 bytes hex');

  // 2. Client encrypts a request to that public key (exactly as the browser does).
  const identity = await Identity.fromPublicKeyHex(pubHex);
  const { request: encReq, context } = await identity.encryptRequestWithContext(
    new Request('https://enclave.ppq.ai/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: REQUEST_BODY,
    }),
  );
  const encapHeader = encReq.headers.get('Ehbp-Encapsulated-Key');
  const encBody = Buffer.from(await encReq.arrayBuffer());
  assert.ok(encapHeader, 'client must set Ehbp-Encapsulated-Key');
  assert.ok(!encBody.includes(Buffer.from('SECRET-INTEROP-CANARY')), 'body must be ciphertext');

  // 3. Enclave decrypts the request.
  const { plaintext, exportedSecret, requestEnc } = await recipient.openRequest(
    encapHeader,
    encBody,
  );
  assert.strictEqual(plaintext.toString('utf8'), REQUEST_BODY, 'request decrypt mismatch');
  console.log('  ✓ request: client-encrypt -> enclave-decrypt matches');

  // 4. Enclave encrypts a streamed response.
  const enc = await recipient.responseEncryptor(exportedSecret, requestEnc);
  const respFrames = [];
  for (const c of RESPONSE_CHUNKS) respFrames.push(await enc.encrypt(Buffer.from(c, 'utf8')));
  const respBody = frames(...respFrames);
  assert.ok(!respBody.includes(Buffer.from('Hello')), 'response body must be ciphertext');

  // 5. Client decrypts the response (as the browser would).
  const clientResp = await identity.decryptResponseWithContext(
    new Response(respBody, { headers: { 'Ehbp-Response-Nonce': enc.responseNonceHex } }),
    context,
  );
  const decoded = await clientResp.text();
  assert.strictEqual(decoded, RESPONSE_CHUNKS.join(''), 'response decrypt mismatch');
  console.log('  ✓ response: enclave-encrypt -> client-decrypt matches');

  console.log('\nEHBP INTEROP OK — enclave recipient is wire-compatible with the ehbp client.');
}

main().catch((e) => {
  console.error('  ✗ INTEROP FAILED:', e.message);
  process.exit(1);
});
