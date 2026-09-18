/**
 * Content-free request trace — what happened to a request, never what was in it.
 *
 * WHY
 * ---
 * A successful private request used to leave horse-power exactly one billing
 * row and nothing else. When a customer asked "why was my request slow / cut
 * off / routed to OpenRouter", support had nothing to look at: every fact that
 * would answer it existed only inside the enclave, in a `log()` nobody can read
 * without `--debug-mode` (which zeroes PCR0). This module assembles the handful
 * of facts that are safe to export — timings, byte counts, the route decision,
 * how the stream ended — so they can ride the settle body (and error reports)
 * and be looked up by credit id.
 *
 * THE CONTAINMENT RULE (same as errorReport.mjs)
 * -----------------------------------------------
 * Nothing from the request or response body ever enters a trace. Every string
 * is either an enum value chosen from a fixed vocabulary or a shape-validated
 * scalar: the caller's request id only if it looks like an id, the User-Agent
 * only if it is printable ASCII and only its first 200 characters, hostnames
 * and provider names only if they are slug-shaped. `client_ip` is the address
 * a listener attached to the socket (`req.socket.clientIp`, set by the PROXY
 * protocol listener on the api port, proxyListener.mjs; absent on the 443
 * path), never a
 * header the caller could set, and only if slug-shaped. Numbers are clamped to
 * non-negative integers. `sanitizeTrace` is the single boundary and is applied
 * to EVERYTHING the recorder builds, so a bug upstream of it cannot widen what
 * leaves.
 *
 * DRIFT HAZARD: the wire shape is mirrored in horse-power (the settle and
 * /enclave/error handlers accept an optional `trace`). Enum additions must land
 * there first.
 */

/** Same shape errorReport.mjs accepts: catalog identifiers, never sentences. */
const LABEL_RE = /^[a-zA-Z0-9._:/@-]{1,96}$/;

/** A caller-supplied correlation id, accepted ONLY in this narrow shape. */
const CLIENT_REQUEST_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Printable ASCII only; the User-Agent is caller-controlled text. */
const PRINTABLE_ASCII_RE = /^[\x20-\x7E]+$/;
const USER_AGENT_MAX = 200;

/** Upstreams the enclave knows how to speak to. Anything else is dropped. */
export const ROUTE_PROVIDERS = Object.freeze([
  'openrouter',
  'fireworks',
  'bedrock',
  'anthropic',
  'vertex',
]);

/** How a response ended, from the enclave's point of view. */
export const STREAM_ENDS = Object.freeze(['clean', 'upstream_error', 'client_abort', 'cap_hit']);

/** Candidate lists are bounded so a pathological hp directive cannot bloat the row. */
const MAX_CANDIDATES = 8;

const PROVIDER_SET = new Set(ROUTE_PROVIDERS);
const STREAM_END_SET = new Set(STREAM_ENDS);

function label(value) {
  if (typeof value !== 'string') return undefined;
  return LABEL_RE.test(value) ? value : undefined;
}

function clientRequestId(value) {
  if (typeof value !== 'string') return undefined;
  return CLIENT_REQUEST_ID_RE.test(value) ? value : undefined;
}

function userAgent(value) {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  const head = value.slice(0, USER_AGENT_MAX);
  return PRINTABLE_ASCII_RE.test(head) ? head : undefined;
}

/** Non-negative integer or undefined. Never NaN, never negative, never a float. */
function nonNegInt(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
  const n = Math.round(value);
  return n >= 0 ? n : undefined;
}

/** Positive integer (1..) or undefined. */
function posInt(value) {
  const n = nonNegInt(value);
  return n !== undefined && n > 0 ? n : undefined;
}

function candidates(list, mapOne) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const item of list) {
    if (out.length >= MAX_CANDIDATES) break;
    const mapped = mapOne(item);
    if (mapped) out.push(mapped);
  }
  return out;
}

function skippedCandidate(s) {
  const provider = label(s?.provider);
  const reason = label(s?.reason);
  if (!provider || !reason) return null;
  const field = label(s?.field);
  return field ? { provider, reason, field } : { provider, reason };
}

/**
 * Failure class from a status, so hp can bucket without parsing: a 5xx from a
 * provider and a connect error look the same to the client (both 502) but
 * mean different things operationally.
 */
export function classifyFailure(status) {
  const n = nonNegInt(status);
  if (n === undefined || n === 0) return 'connect_error';
  if (n >= 500) return 'http_5xx';
  if (n >= 400) return 'http_4xx';
  return 'http_other';
}

function failedCandidate(f) {
  const provider = label(f?.provider);
  if (!provider) return null;
  const status = posInt(f?.status);
  const cls = label(f?.class) ?? classifyFailure(f?.status);
  const out = { provider };
  if (status !== undefined) out.status = status;
  out.class = cls;
  return out;
}

/**
 * `chosen` is optional: when no upstream served (every candidate skipped or
 * failed) the skipped/failed lists are the most useful part of the trace, so
 * the route is kept whenever it says anything at all and dropped only when it
 * says nothing.
 */
function route(r) {
  if (!r || typeof r !== 'object') return undefined;
  const chosen = typeof r.chosen === 'string' && PROVIDER_SET.has(r.chosen) ? r.chosen : undefined;
  const skipped = candidates(r.skipped, skippedCandidate);
  const failed = candidates(r.failed, failedCandidate);
  if (!chosen && skipped.length === 0 && failed.length === 0) return undefined;
  const out = {};
  if (chosen) out.chosen = chosen;
  const host = label(r.upstream_host);
  if (host) out.upstream_host = host;
  const style = label(r.api_style);
  if (style) out.api_style = style;
  out.skipped = skipped;
  out.failed = failed;
  return out;
}

function enclave(e) {
  if (!e || typeof e !== 'object') return undefined;
  const out = {};
  const version = label(e.version);
  if (version) out.version = version;
  const worker = nonNegInt(e.worker);
  out.worker = worker ?? 0;
  const box = label(e.box);
  if (box) out.box = box;
  return out;
}

/**
 * Enforce every bound on a candidate trace object. Pure; returns a NEW object
 * containing only allowlisted fields in allowlisted shapes, or null when the
 * input is not an object. Whatever a caller passes, nothing else comes out.
 */
export function sanitizeTrace(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const out = {};
  const crid = clientRequestId(obj.client_request_id);
  if (crid) out.client_request_id = crid;
  const ua = userAgent(obj.user_agent);
  if (ua) out.user_agent = ua;
  const ip = label(obj.client_ip);
  if (ip) out.client_ip = ip;
  out.streaming = obj.streaming === true;
  out.ehbp = obj.ehbp === true;
  const tAuth = nonNegInt(obj.t_authorize_ms);
  if (tAuth !== undefined) out.t_authorize_ms = tAuth;
  const tConn = nonNegInt(obj.t_upstream_connect_ms);
  if (tConn !== undefined) out.t_upstream_connect_ms = tConn;
  const tFirst = nonNegInt(obj.t_first_token_ms);
  if (tFirst !== undefined) out.t_first_token_ms = tFirst;
  out.t_total_ms = nonNegInt(obj.t_total_ms) ?? 0;
  out.bytes_out = nonNegInt(obj.bytes_out) ?? 0;
  const r = route(obj.route);
  if (r) out.route = r;
  if (typeof obj.stream_end === 'string' && STREAM_END_SET.has(obj.stream_end)) {
    out.stream_end = obj.stream_end;
  }
  out.max_tokens_cap_applied = obj.max_tokens_cap_applied === true;
  const cap = posInt(obj.max_tokens_cap);
  if (cap !== undefined) out.max_tokens_cap = cap;
  const e = enclave(obj.enclave);
  if (e) out.enclave = e;
  return out;
}

/** The marks the recorder understands; anything else is ignored. */
export const MARKS = Object.freeze(['start', 'authorized', 'upstreamHeaders', 'firstByte', 'end']);

/**
 * Per-request recorder. Every method is a no-throw setter; the only place that
 * decides what leaves is `build()`, which routes through `sanitizeTrace`.
 *
 * `mark(name)` records the FIRST occurrence of each mark only, so a stream that
 * writes ten thousand chunks can call `mark('firstByte')` on every one of them
 * without the timing drifting.
 *
 * @param {object} [o]
 * @param {() => number} [o.now]  clock (injectable for tests); defaults to Date.now
 */
export function createTraceRecorder({ now = () => Date.now() } = {}) {
  const marks = Object.create(null);
  const state = {
    client_request_id: undefined,
    user_agent: undefined,
    client_ip: undefined,
    streaming: true,
    ehbp: false,
    bytes_out: 0,
    route: undefined,
    stream_end: undefined,
    max_tokens_cap_applied: false,
    max_tokens_cap: undefined,
    enclave: undefined,
  };

  function mark(name) {
    if (typeof name !== 'string' || !MARKS.includes(name)) return;
    if (marks[name] !== undefined) return;
    const t = now();
    marks[name] = typeof t === 'number' && Number.isFinite(t) ? t : 0;
  }

  // The recorder exists from the moment the request arrives; `start` is the
  // reference every other mark is measured from.
  mark('start');

  function since(name) {
    if (marks[name] === undefined || marks.start === undefined) return undefined;
    return Math.max(0, marks[name] - marks.start);
  }

  return {
    mark,
    /** Bytes written to the client; ignored unless a positive finite number. */
    addBytes(n) {
      if (typeof n === 'number' && Number.isFinite(n) && n > 0) state.bytes_out += n;
    },
    /** Caller-visible facts from the request HEADERS (never the body). */
    setClient({ requestId, userAgent: ua, clientIp } = {}) {
      state.client_request_id = requestId;
      state.user_agent = ua;
      state.client_ip = clientIp;
    },
    setStreaming(v) {
      state.streaming = v === true;
    },
    setEhbp(v) {
      state.ehbp = v === true;
    },
    /**
     * The route decision, in the same terms buildReceipt uses: `chosen` is the
     * provider served, `skipped` / `failed` are the candidates ahead of it and
     * why they were not used.
     */
    setRoute({ chosen, upstreamHost, apiStyle, skipped, failed } = {}) {
      state.route = {
        chosen,
        upstream_host: upstreamHost,
        api_style: apiStyle,
        skipped,
        failed,
      };
    },
    /** First writer wins: a client abort followed by the upstream's `end` stays an abort. */
    setStreamEnd(kind) {
      if (state.stream_end !== undefined) return;
      if (typeof kind === 'string' && STREAM_END_SET.has(kind)) state.stream_end = kind;
    },
    streamEnd() {
      return state.stream_end;
    },
    setMaxTokensCap({ applied, cap } = {}) {
      state.max_tokens_cap_applied = applied === true;
      state.max_tokens_cap = cap;
    },
    setEnclave({ version, worker, box } = {}) {
      state.enclave = { version, worker, box };
    },
    /**
     * The sanitized trace. `t_total_ms` is measured to the `end` mark when one
     * exists, else to now — an error report mid-request still gets a duration.
     */
    build() {
      const endAt = marks.end !== undefined ? marks.end : now();
      const total =
        marks.start !== undefined && typeof endAt === 'number' ? Math.max(0, endAt - marks.start) : 0;
      return sanitizeTrace({
        ...state,
        t_authorize_ms: since('authorized'),
        t_upstream_connect_ms: since('upstreamHeaders'),
        t_first_token_ms: since('firstByte'),
        t_total_ms: total,
      });
    },
  };
}
