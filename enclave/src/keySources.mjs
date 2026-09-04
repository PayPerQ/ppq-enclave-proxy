// Which delivery path produced each provider secret at boot.
//
// WHY THIS EXISTS
// ---------------
// `boot.sh` prefers an attestation-gated KMS decrypt and falls back to the
// plaintext init channel when that is unavailable or fails. The fallback is
// correct — a key problem must never cost users their answers — but it made a
// working KMS decrypt and a silently failed one indistinguishable from outside.
//
// It announces the path it took with log(), which writes to the enclave
// console. Reading that console requires `--debug-mode`, and debug mode zeroes
// every PCR, so it can never be enabled on the production enclave: every pinned
// client would reject an all-zero measurement. The path was therefore
// unobservable in the only environment where it matters.
//
// That gap is not hypothetical. The CMK's attestation allow-list sat naming two
// retired measurements while production ran a third (#11) — a state in which
// every gated decrypt would have been denied — and nothing noticed, because
// nothing exercised the path and nothing could see which path ran.
//
// WHAT IS SAFE TO REPORT
// ----------------------
// The NAME of the branch taken. Never key material, never a length, never
// anything derived from a secret — a length is a distinguisher, and this
// endpoint is public. `absent` already tells a reader a key was not supplied,
// which is deployment shape rather than secret content.
//
// TRUST LEVEL: this is a DIAGNOSTIC, not an attested claim. nginx terminates
// TLS on the public path today, so the parent could rewrite this field — the
// same reason routing receipts ride inside the sealed body rather than a header
// (#58). Acceptable here because the purpose is verifying our own deployment
// against our own pipeline, not defending against an adversary. If it ever
// needs to resist one, it belongs in the sealed channel or the attestation
// document itself.

/** The delivery paths boot.sh can report. Anything else is a bug or tampering. */
export const KEY_SOURCE_VALUES = Object.freeze([
  // Attestation-gated KMS decrypt succeeded. The goal state.
  'kms',
  // No ciphertext was supplied; the key arrived over the plaintext init channel.
  'init-plaintext',
  // Ciphertext WAS supplied, the decrypt failed, and the plaintext fallback
  // covered it. Kept distinct from `init-plaintext` because this is the silent
  // failure — everything keeps working while the gating does nothing.
  'init-plaintext-after-kms-failure',
  // Ciphertext supplied, decrypt failed, and no fallback was available.
  'kms-failed',
  // No key supplied at all; the provider is simply not configured.
  'absent',
]);

/** The env var boot.sh exports for each secret. */
const SOURCE_ENV = Object.freeze({
  openrouter: 'OPENROUTER_KEY_SOURCE',
  fireworks: 'FIREWORKS_KEY_SOURCE',
  anthropic: 'ANTHROPIC_KEY_SOURCE',
  vertex: 'VERTEX_KEY_SOURCE',
});

/**
 * Normalise one marker.
 *
 * An unset variable reports `unknown` rather than guessing `absent`: an older
 * boot.sh that predates this instrumentation is a genuinely different situation
 * from a key that was not supplied, and reporting the second when the first is
 * true would be a false all-clear on exactly the question this answers.
 */
function normalise(raw) {
  if (raw === undefined || raw === null || raw === '') return 'unknown';
  return KEY_SOURCE_VALUES.includes(raw) ? raw : 'unrecognized';
}

/** `{ openrouter: 'kms', anthropic: 'init-plaintext', ... }` */
export function keySources(env = process.env) {
  const out = {};
  for (const [name, varName] of Object.entries(SOURCE_ENV)) {
    out[name] = normalise(env[varName]);
  }
  return out;
}

/**
 * Whether a reported source means the secret bypassed attestation gating.
 *
 * `absent` is NOT degraded — a provider that is not configured cannot be
 * ungated. Callers asserting "this secret must arrive over KMS" should check
 * for `kms` directly rather than inverting this.
 */
export function isDegradedSource(source) {
  return source !== 'kms' && source !== 'absent';
}
