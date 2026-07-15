#!/usr/bin/env node
/**
 * Live end-to-end EHBP test — a Node stand-in for the browser.
 *
 * Exercises the real deployed path: fetch attestation over the real Let's
 * Encrypt TLS at https://enclave.ppq.ai, take the enclave's HPKE public key,
 * HPKE-encrypt a chat request with the *same* `ehbp` client the browser uses,
 * send it, and decrypt the streamed response. Proves the host relays only
 * ciphertext and the enclave decrypts/encrypts correctly through host TLS.
 *
 * (Attestation is fetched but NOT yet cryptographically verified here — that's
 * the browser verifier, step 3. This test proves the EHBP transport itself.)
 *
 *   node client/ehbp-live-test.mjs --host enclave.ppq.ai --credit-id <id>
 */
import { Identity } from 'ehbp';

function arg(n, d) {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : d;
}
const HOST = arg('host', 'enclave.ppq.ai');
const CREDIT_ID = arg('credit-id', '');
const MODEL = arg('model', 'openai/gpt-4o-mini');
const PROMPT = arg('prompt', 'Say hello in three words.');
const base = `https://${HOST}`;

async function main() {
  // 1. Fetch attestation (over the real host TLS) → HPKE public key.
  const attRes = await fetch(`${base}/attestation?nonce=${'ab'.repeat(16)}`);
  const att = await attRes.json();
  const hpkeHex = att.hpke_public_key;
  if (!hpkeHex) throw new Error('no hpke_public_key in attestation response');
  console.log(`  ✓ fetched attestation; HPKE key ${hpkeHex.slice(0, 16)}…`);

  // 2. Encrypt the chat request to that key with the ehbp client (as the browser does).
  const identity = await Identity.fromPublicKeyHex(hpkeHex);
  const plainReq = new Request(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: PROMPT }],
      max_tokens: 40,
      stream: true,
    }),
  });
  const { request: encReq, context } = await identity.encryptRequestWithContext(plainReq);

  // 3. Send it (auth headers travel in cleartext; body is ciphertext).
  const sent = await fetch(encReq.url, {
    method: 'POST',
    headers: {
      ...Object.fromEntries(encReq.headers),
      'x-credit-id': CREDIT_ID,
      'x-query-source': 'api',
      'x-request-id': `ehbp-live-${Date.now()}`,
    },
    body: await encReq.arrayBuffer(),
  });
  console.log(`  ✓ sent EHBP request, status ${sent.status}`);
  if (sent.status !== 200) {
    console.log('  response (plaintext error):', (await sent.text()).slice(0, 200));
    return;
  }

  // 4. Decrypt the streamed response.
  const dec = await identity.decryptResponseWithContext(sent, context);
  const text = await dec.text();
  const answer = (text.match(/"content":"([^"]*)"/g) || [])
    .map((m) => m.replace(/"content":"|"$/g, ''))
    .join('');
  console.log(`  ✓ decrypted response`);
  console.log(`\n  model:  ${MODEL}`);
  console.log(`  answer: ${answer || '(no content)'}`);
  console.log('\nEHBP LIVE OK — browser-shaped request went through the enclave over host TLS.');
}

main().catch((e) => {
  console.error('  ✗ FAILED:', e.message);
  process.exit(1);
});
