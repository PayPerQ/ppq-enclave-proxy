/**
 * Per-worker request counters for /health.
 *
 * Content-free by construction: every key is an enum value the enclave itself
 * chose (an outcome code, a provider name) and every value is an integer. The
 * key sets are bounded so a bug that fed caller text into a bump could not
 * grow the health body without limit — an unknown key is still counted, but
 * under `other`, and the map stops accepting NEW keys past the cap.
 *
 * Per WORKER, not per box: the cluster's workers do not share memory, and
 * /health is answered by whichever worker took the connection. Sum across
 * workers (or poll each) for a box-wide view; `worker` on the same body says
 * which one answered.
 *
 * INVARIANT — exactly one outcome per request, so `by_outcome` sums to
 * `requests` once every request has finished. `beginRequest()` counts the
 * request and hands back a `finalize(outcome)` that records the outcome once
 * and ignores every later call; server.mjs calls it on every early return
 * (with the error code, or `unauthenticated` for a missing credential), at
 * the terminal stream end (`clean` / `cap_hit` / `upstream_error` /
 * `client_abort`), and when a passed-through upstream error status is the
 * answer (`upstream_error_status`). Error REPORTS are a different thing: one
 * request can send several (a skipped direct candidate, a passed-through 4xx
 * that then streams cleanly, a settle that fails later) and a report is not
 * an outcome, so they are counted separately under `error_reports`, one per
 * report ATTEMPTED (counted before the send, so a report the enclave could not
 * deliver, or did not send because no settle host is configured, still counts). Settle losses are counted only under `settle.permanent_failures`.
 * The first version counted reports as outcomes and put an aborted request in
 * `by_outcome` twice (`{clean:1, client_abort:2}` for two requests).
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
    error_reports: Object.create(null),
    ehbp: 0,
    streaming: 0,
    open_streams: 0,
    settle_permanent_failures: 0,
  };
  return {
    /**
     * Count a request and return its `finalize(outcome)`: the ONE call that
     * records this request's outcome. Every call after the first is a no-op,
     * which is what lets a terminal early return and a later stream end both
     * call it without the request being counted twice.
     */
    beginRequest() {
      c.requests += 1;
      let done = false;
      return (outcome) => {
        if (done) return;
        done = true;
        bump(c.by_outcome, outcome);
      };
    },
    /** One per error report SENT (not per request). Telemetry, not an outcome. */
    errorReport(code) {
      bump(c.error_reports, code);
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
        error_reports: { ...c.error_reports },
        ehbp: c.ehbp,
        streaming: c.streaming,
        open_streams: c.open_streams,
        settle: { queued, permanent_failures: c.settle_permanent_failures },
      };
    },
  };
}
