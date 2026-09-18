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

/**
 * Normalise an operator-supplied pin: 64 hex digits in any case, optionally
 * separated by colons or spaces (as `openssl` and some UIs print them).
 * Anything else is refused rather than silently stripped, so a typo cannot
 * hide inside a value that happens to still contain a valid pin.
 */
export function normalizePin(pin) {
  const raw = String(pin || '');
  if (!/^[0-9a-fA-F:\s]+$/.test(raw)) throw new Error('--pin-spki may contain only hex digits, colons and spaces');
  const p = raw.toLowerCase().replace(/[:\s]/g, '');
  if (p.length !== 64) throw new Error(`--pin-spki must be a sha256 (64 hex digits), got ${p.length}`);
  return p;
}
