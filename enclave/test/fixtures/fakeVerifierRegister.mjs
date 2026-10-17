// `node --import` preload for the PII integration tests' server child process:
// swaps the SEV-SNP/Sigstore verifier for fakeTinfoilVerifier.mjs, so a fake
// detector can present an attestation. The production code path is unchanged.
import { register } from 'node:module';

register('./fakeVerifierHooks.mjs', import.meta.url);
