/**
 * Primary <-> worker protocol for the in-enclave cluster (#52 scaling, step 5).
 *
 * WHY A CLUSTER AT ALL
 * --------------------
 * The enclave is one Node event loop. A bigger instance changes nothing until
 * there is more than one loop -- the same lesson horse-power learned. Node's
 * `cluster` gives N loops sharing one listening socket, and everything that
 * must be single-writer stays in the PRIMARY: unsealing the store, the EHBP
 * identity, ACME orders and store saves, and the host's credential pushes.
 * Workers only serve. All of it is inside the same measured image, so handing
 * private material over IPC crosses no trust boundary.
 *
 * WHAT CROSSES IPC, AND WHY EACH IS NEEDED
 *   state            everything a worker needs to serve: the EHBP identity
 *                    (private key included), the issued certificates, the
 *                    provenance fields /health reports, the last Bedrock blob.
 *   acme-challenge   a TLS-ALPN-01 challenge certificate. The validating
 *                    handshake lands on whichever worker the kernel picks, so
 *                    EVERY worker must hold it before the CA is told to
 *                    validate -- hence it is acknowledged, and the order waits.
 *   acme-clear       disarm that challenge everywhere.
 *   acme-issued      a newly issued certificate, installed under every name --
 *                    sent the moment it is installed in the primary, BEFORE it
 *                    is sealed and saved, so a persistence failure cannot leave
 *                    workers on the old certificate.
 *   health           provenance fields that change after the fact (e.g.
 *                    hpke_identity_persisted once the store save completes).
 *   bedrock-creds    a host-pushed credential blob; each worker applies it
 *                    itself (the KMS decrypt is per process and cheap).
 *   listening        a worker has bound the shared port. The primary places a
 *                    pending ACME order only once every worker reports this.
 *   ack              a worker has applied an acknowledged message.
 *   rpc / rpc-reply  a worker asks the primary to do single-writer work on a
 *                    request's behalf and relays the answer (#52 DNS-01: the
 *                    CSR over the pending renewal key, installing the result).
 *
 * LIFECYCLE RULES (Codex review, 2026-09-08)
 *   - Active challenges live in the primary and are part of `state`, so a
 *     worker respawned mid-order installs them BEFORE it listens.
 *   - A worker that dies is dropped from every pending ack set; its
 *     replacement gets the same material through `state`, never through a
 *     replay the primary has to remember.
 *   - `acme-clear` is acknowledged too, but never fails an order: the order
 *     is already decided by then, and a stale challenge cert is a worker that
 *     will be fixed by the next message, not a reason to lose a certificate.
 *   - Readiness is the SET of listening worker ids, not a counter.
 *   - Respawn backs off and gives up: ten fast failures in a row exit the
 *     primary, which takes the enclave down visibly instead of spinning.
 *
 * `ENCLAVE_WORKERS` unset, empty, non-numeric or <= 1 means NO cluster: one
 * process, exactly the behaviour before this existed. The knob is set from
 * the init blob when the instance is sized for it.
 */

export const MSG = Object.freeze({
  STATE: 'state',
  CHALLENGE: 'acme-challenge',
  CHALLENGE_CLEAR: 'acme-clear',
  ISSUED: 'acme-issued',
  BEDROCK: 'bedrock-creds',
  HEALTH: 'health',
  LISTENING: 'listening',
  ACK: 'ack',
  // Worker -> primary request/reply, for the few things a worker must ask the
  // primary to do (CI-driven renewal: hand out a CSR, install a certificate).
  RPC: 'rpc',
  RPC_REPLY: 'rpc-reply',
});

/** More than this is a typo, not a plan; the biggest enclave-capable box has 128 vCPU. */
export const MAX_WORKERS = 64;

/** How many worker processes `env` asks for; 1 means "no cluster". */
export function workerCount(env = process.env) {
  const n = Number.parseInt(String(env.ENCLAVE_WORKERS ?? '').trim(), 10);
  if (!Number.isFinite(n) || n <= 1) return 1;
  return Math.min(n, MAX_WORKERS);
}

/** A message is only ever an object with a known `type`. Anything else is dropped. */
export function isMessage(m) {
  return Boolean(m) && typeof m === 'object' && Object.values(MSG).includes(m.type);
}
