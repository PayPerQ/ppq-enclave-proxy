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
 *
 * INVARIANT — one outcome per request: a stream end for successes, an error
 * code for failures. `by_outcome` therefore sums to (at most) `requests`.
 * Failures are counted where they are reported (server.mjs
 * `reportEnclaveError` calls `outcome(code)` for every code it sends), so the
 * stream-end path must NOT count the failure ends as well: `client_abort`
 * already arrived as the `client_abort` report, and `upstream_error` as
 * `stream_failed`. Counting both put an aborted request in `by_outcome` twice
 * (seen on the dev enclave: `{clean:1, client_abort:2}` for two requests).
 * `streamEnd()` enforces this by counting only the non-failure ends.
 */

/** Stream ends that are the request's outcome in their own right. */
export const SUCCESS_STREAM_ENDS = Object.freeze(['clean', 'cap_hit']);

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
    /** A failure outcome: called once per error report, with the code. */
    outcome(key) {
      bump(c.by_outcome, key);
    },
    /**
     * A stream end. Counted ONLY when it is a success (`clean`, `cap_hit`);
     * a failure end was already counted as its error code (see the invariant
     * above), so recording it here would count the request twice.
     */
    streamEnd(kind) {
      if (typeof kind === 'string' && SUCCESS_STREAM_ENDS.includes(kind)) bump(c.by_outcome, kind);
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
