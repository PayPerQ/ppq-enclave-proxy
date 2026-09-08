/**
 * Which EHBP identity this process presents (#52 scaling).
 *
 * Two answers, and the difference is visible on /health as `hpke_identity`:
 *
 *   store      the identity unsealed from the certificate store -- what every
 *              restart, and later every box in a fleet, should report;
 *   generated  a fresh keypair, because the store held none (first boot with
 *              this feature, or no store at all) or held one that failed to
 *              load.
 *
 * A stored identity that fails to load is logged and REPLACED, never fatal:
 * an enclave that refuses to boot over its EHBP key takes the plain-TLS path
 * down with it, and that path does not need this key at all. But it must be
 * loud, because a store that keeps failing means every restart is silently
 * rotating the key browsers seal to -- the exact behaviour this exists to end.
 */

import { EhbpRecipient } from './ehbp-server.mjs';

export const HPKE_IDENTITY_SOURCES = Object.freeze(['store', 'generated']);

/**
 * @param {{stored?: object|null, log?: (m: string) => void}} opts
 * @returns {Promise<{recipient: EhbpRecipient, source: 'store'|'generated'}>}
 */
export async function resolveHpkeIdentity({ stored = null, log = () => {} } = {}) {
  if (stored) {
    try {
      const recipient = await EhbpRecipient.fromJSON(stored);
      return { recipient, source: 'store' };
    } catch (e) {
      log(`hpke-identity: stored identity rejected (${e.message}); generating a fresh one`);
    }
  }
  return { recipient: await EhbpRecipient.generate(), source: 'generated' };
}
