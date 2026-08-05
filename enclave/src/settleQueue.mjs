/**
 * Durable settlement retry queue (issue #5).
 *
 * A dropped settle = a paid query billed to nobody (revenue leak), and the cost
 * exists ONLY here in the enclave (parsed from the OpenRouter stream), so
 * horse-power can't reconstruct it after the fact. This retries transient
 * failures with exponential backoff until horse-power acknowledges. Settlement
 * is idempotent (hp dedupes by request_id and returns 200 `duplicate:true`), so
 * a retry after a slow/lost success is a harmless no-op.
 *
 * In-memory only — an enclave crash still loses the queue. That window (crash
 * AFTER OpenRouter responds but BEFORE hp acks a retry) is tiny and unavoidable:
 * the only durable store is hp itself, reached via the very call that's failing.
 * This covers the common case (hp restart/deploy, network blip, transient 5xx).
 *
 * Pure and injectable: `post`, `now`, `log`, and the timer are all injected so
 * the queue logic is unit-testable without https or a running enclave.
 */

/**
 * Map an HTTP status to a retry decision.
 *  - 2xx            → 'ok'        (billed, or idempotent duplicate)
 *  - 400 / 401      → 'permanent' (bad payload / bad enclave secret — a retry
 *                     can never succeed; drop and alert)
 *  - everything else→ 'transient' (5xx, 0/no-response — retry)
 */
export function classifySettleStatus(status) {
  if (status >= 200 && status < 300) return 'ok';
  if (status === 400 || status === 401) return 'permanent';
  return 'transient';
}

/** Exponential backoff with a cap: base*2^attempts, clamped to `cap` ms. */
export function backoffMs(attempts, base = 1000, cap = 120_000) {
  return Math.min(cap, base * 2 ** attempts);
}

/**
 * @param {object} o
 * @param {(meta:any)=>Promise<'ok'|'permanent'|'transient'>} o.post  one settle attempt
 * @param {()=>number} [o.now]        clock (injectable for tests)
 * @param {(msg:string)=>void} [o.log]
 * @param {number} [o.maxAttempts]    give up (and log a lost-revenue error) after this many tries
 * @param {number} [o.cap]            max queued items; drop-oldest beyond this to bound enclave memory
 * @param {number} [o.drainMs]        drain tick interval
 * @param {(fn:()=>void, ms:number)=>any} [o.setTimer]  injectable (default setInterval)
 */
export function createSettleQueue({
  post,
  now = () => Date.now(),
  log = () => {},
  maxAttempts = 10,
  cap = 10_000,
  drainMs = 2_000,
  setTimer = (fn, ms) => setInterval(fn, ms),
}) {
  /** @type {{meta:any, attempts:number, nextAt:number, inFlight:boolean}[]} */
  const queue = [];

  function remove(item) {
    const i = queue.indexOf(item);
    if (i >= 0) queue.splice(i, 1);
  }

  function enqueue(meta, attempts) {
    if (queue.length >= cap) {
      const dropped = queue.shift();
      log(
        `settle queue full (cap=${cap}) — DROPPED req=${dropped?.meta?.request_id} (revenue lost)`,
      );
    }
    queue.push({ meta, attempts, nextAt: now() + backoffMs(attempts), inFlight: false });
  }

  /** Try once immediately; enqueue for retry only on a transient failure. */
  function submit(meta) {
    return post(meta).then((outcome) => {
      if (outcome === 'transient') {
        enqueue(meta, 1);
      } else if (outcome === 'permanent') {
        log(`settle PERMANENT-FAIL req=${meta.request_id} — not retrying`);
      }
      return outcome;
    });
  }

  /** Process every due, not-in-flight item once. Safe to call repeatedly. */
  function drainTick() {
    const t = now();
    for (const item of [...queue]) {
      if (item.inFlight || item.nextAt > t) continue;
      item.inFlight = true;
      post(item.meta).then((outcome) => {
        item.inFlight = false;
        if (outcome === 'ok' || outcome === 'permanent') {
          if (outcome === 'permanent') {
            log(`settle PERMANENT-FAIL req=${item.meta.request_id} — dropping`);
          }
          remove(item);
          return;
        }
        item.attempts += 1;
        if (item.attempts > maxAttempts) {
          remove(item);
          log(
            `settle GAVE UP after ${maxAttempts} attempts req=${item.meta.request_id} (revenue lost — needs reconciliation)`,
          );
          return;
        }
        item.nextAt = now() + backoffMs(item.attempts);
      });
    }
  }

  const timer = setTimer(drainTick, drainMs);

  return {
    submit,
    drainTick,
    size: () => queue.length,
    stop: () => clearInterval(timer),
    _queue: queue, // exposed for tests/inspection
  };
}
