// The one number a verifying client compares: sha256 over the DER
// SubjectPublicKeyInfo of a certificate, lower-case hex, the same value the
// enclave commits to its attestation document as `cert_spki_sha256` and that
// scripts/check-live-attestation.mjs checks the served certificate against.
import { createHash, X509Certificate } from 'node:crypto';

/** @param {Buffer} rawDer a certificate in DER, e.g. socket.getPeerCertificate(false).raw */
export function spkiSha256Hex(rawDer) {
  const der = new X509Certificate(rawDer).publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

/** Normalise an operator-supplied pin: hex, any case, optional colons/spaces. */
export function normalizePin(pin) {
  const p = String(pin || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (p.length !== 64) throw new Error(`--pin-spki must be a sha256 (64 hex chars), got ${String(pin).length} chars`);
  return p;
}
