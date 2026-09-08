/**
 * Which EHBP identity this process presents (#52 scaling).
 *
 * Three answers, and the difference is visible on /health as `hpke_identity`:
 *
 *   store      the identity unsealed from the certificate store -- what every
 *              restart, and later every box in a fleet, should report;
 *   generated  the store held NO identity (first boot with this feature, or no
 *              store at all): a fresh keypair, which the caller persists so it
 *              is fresh exactly once;
 *   rejected   the store held an identity and it FAILED to load. The store
 *              authenticated those bytes, so this is a version bug, a bad
 *              manual edit or a truncated write -- never a legitimate reason
 *              to mint a new key. A fresh keypair is served so the enclave
 *              stays up, but the caller must NOT write it over the store:
 *              doing so would turn any of those faults into a silent
 *              fleet-wide key rotation that also destroys the evidence.
 *
 * None of these is fatal: an enclave that refuses to boot over its EHBP key
 * takes the plain-TLS path down with it, and that path does not need this key.
 * `rejected` is loud on purpose -- the drift check treats anything but `store`
 * as a problem.
 */

import { EhbpRecipient } from './ehbp-server.mjs';

export const HPKE_IDENTITY_SOURCES = Object.freeze(['store', 'generated', 'rejected']);

/**
 * @param {{stored?: object|null, log?: (m: string) => void}} opts
 * @returns {Promise<{recipient: EhbpRecipient, source: 'store'|'generated'|'rejected', reason?: string}>}
 */
export async function resolveHpkeIdentity({ stored = null, log = () => {} } = {}) {
  if (stored != null) {
    try {
      const recipient = await EhbpRecipient.fromJSON(stored);
      return { recipient, source: 'store' };
    } catch (e) {
      log(
        `hpke-identity: stored identity REJECTED (${e.message}); serving a fresh key this boot ` +
        'and leaving the store untouched',
      );
      return { recipient: await EhbpRecipient.generate(), source: 'rejected', reason: e.message };
    }
  }
  return { recipient: await EhbpRecipient.generate(), source: 'generated' };
}
