/**
 * Test the isomorphic browser verifier against the LIVE enclave attestation.
 *   node client/browser-verify.test.mjs --host enclave.ppq.ai --expect-pcr0 <hex>
 */
import { verifyAttestation, bytesToHex } from './browser-verify.mjs';

function arg(n, d) {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : d;
}
const HOST = arg('host', 'enclave.ppq.ai');
const PCR0 = arg('expect-pcr0', '');

async function fetchAtt(nonceHex) {
  const r = await fetch(`https://${HOST}/attestation?nonce=${nonceHex}`);
  return r.json();
}

async function main() {
  const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));

  // Positive
  const att = await fetchAtt(nonce);
  const { hpkePublicKeyHex, pcrs } = await verifyAttestation(att.attestation_document_b64, {
    expectedPcr0: PCR0,
    nonceHex: nonce,
  });
  console.log('  ✓ attestation verified (sig + AWS chain + CA constraints + nonce + PCR0)');
  console.log(`    PCR0 = ${pcrs[0].slice(0, 24)}…`);
  if (hpkePublicKeyHex !== att.hpke_public_key)
    throw new Error('verified HPKE key != endpoint-reported key');
  console.log(`  ✓ HPKE key extracted + matches endpoint (${hpkePublicKeyHex.slice(0, 16)}…)`);

  // Negative: wrong PCR0 must throw
  try {
    await verifyAttestation(att.attestation_document_b64, {
      expectedPcr0: 'dead'.repeat(24),
      nonceHex: nonce,
    });
    throw new Error('SHOULD HAVE REJECTED wrong PCR0');
  } catch (e) {
    if (/SHOULD HAVE/.test(e.message)) throw e;
    console.log(`  ✓ wrong PCR0 correctly rejected (${e.message.split('\n')[0]})`);
  }

  console.log('\nBROWSER VERIFIER OK — verifies the live enclave and yields the HPKE key.');
}
main().catch((e) => {
  console.error('  ✗ FAILED:', e.message);
  process.exit(1);
});
