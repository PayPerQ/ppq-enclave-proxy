/**
 * Per-worker request counters for /health.
 *
 * Content-free by construction: every key is an enum value the enclave itself
 * chose (an outcome code, a provider name) and every value is an integer. The
 * key sets are bounded so a bug that fed caller text into `outcome()` could not
 * grow the health body without limit — an unknown key is still counted, but
 * under `other`, and the map stops accepting NEW keys past the cap.
 *
 * Per WORKER, not per box: the cluster's workers do not share memory, and
 * /health is answered by whichever worker took the connection. Sum across
 * workers (or poll each) for a box-wide view; `worker` on the same body says
 * which one answered.
 */

const KEY_RE = /^[a-z0-9_]{1,64}$/;
/** Total keys per map, `other` included — so at most MAX_KEYS - 1 named ones. */
const MAX_KEYS = 64;

function bump(map, key) {
  let k = typeof key === 'string' && KEY_RE.test(key) ? key : 'other';
  if (k !== 'other' && map[k] === undefined) {
    const named = Object.keys(map).filter((x) => x !== 'other').length;
    if (named >= MAX_KEYS - 1) k = 'other';
  }
  map[k] = (map[k] ?? 0) + 1;
}

export function createCounters() {
  const c = {
    requests: 0,
    by_outcome: Object.create(null),
    by_provider: Object.create(null),
    ehbp: 0,
    streaming: 0,
    open_streams: 0,
    settle_permanent_failures: 0,
  };
  return {
    request() {
      c.requests += 1;
    },
    /** One request may record several outcomes (an error code AND a stream end). */
    outcome(key) {
      bump(c.by_outcome, key);
    },
    provider(name) {
      bump(c.by_provider, name);
    },
    ehbp() {
      c.ehbp += 1;
    },
    streaming() {
      c.streaming += 1;
    },
    streamOpened() {
      c.open_streams += 1;
    },
    streamClosed() {
      if (c.open_streams > 0) c.open_streams -= 1;
    },
    settlePermanentFailure() {
      c.settle_permanent_failures += 1;
    },
    /**
     * The /health shape. `queued` is read from the settle queue at call time
     * rather than tracked here, because the queue already knows its own size.
     */
    snapshot({ settleQueued = 0 } = {}) {
      const queued =
        typeof settleQueued === 'number' && Number.isFinite(settleQueued) && settleQueued > 0
          ? Math.floor(settleQueued)
          : 0;
      return {
        requests: c.requests,
        by_outcome: { ...c.by_outcome },
        by_provider: { ...c.by_provider },
        ehbp: c.ehbp,
        streaming: c.streaming,
        open_streams: c.open_streams,
        settle: { queued, permanent_failures: c.settle_permanent_failures },
      };
    },
  };
}
