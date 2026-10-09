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
 * path). What that address is, and is not: it is asserted by the HOST (nginx
 * behind the load balancer), exactly like the load balancer's own view of the
 * peer -- its integrity rests on the host, it is not part of the privacy
 * claim (the threat model already states the parent sees IPs and metadata),
 * and horse-power uses it for the decisions it already makes from Azure's
 * X-Client-IP: sanctions, per-IP limits, support identity. There is no
 * trusted edge that could sign it, so the MAC on the wire binds only the
 * value the enclave saw. Never a
 * header the caller could set, and only if slug-shaped. Numbers are clamped to
 * non-negative integers. `sanitizeTrace` is the single boundary and is applied
 * to EVERYTHING the recorder builds, so a bug upstream of it cannot widen what
 * leaves.
 *
 * DRIFT HAZARD: the wire shape is mirrored in horse-power (the settle and
 * /enclave/error handlers accept an optional `trace`). Enum additions must land
 * there first.
 */

import { performance } from 'node:perf_hooks';

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
  'firerouter',
  'bedrock',
  'anthropic',
  'vertex',
]);

/** How a response ended, from the enclave's point of view. */
export const STREAM_ENDS = Object.freeze(['clean', 'upstream_error', 'client_abort', 'cap_hit']);

/**
 * What the first generated token was: visible answer text, or
 * reasoning the model streams before answering. Kept apart so a reasoning
 * model's time-to-first-token is never silently compared with a plain one.
 */
export const FIRST_TOKEN_KINDS = Object.freeze(['content', 'reasoning']);

/** Candidate lists are bounded so a pathological hp directive cannot bloat the row. */
const MAX_CANDIDATES = 8;

const PROVIDER_SET = new Set(ROUTE_PROVIDERS);
const STREAM_END_SET = new Set(STREAM_ENDS);
const FIRST_TOKEN_KIND_SET = new Set(FIRST_TOKEN_KINDS);

function label(value) {
  if (typeof value !== 'string') return undefined;
  return LABEL_RE.test(value) ? value : undefined;
}

/**
 * The request's correlation id if it has the accepted shape, else undefined.
 * Exported so every place the id leaves the enclave bounds it the same way.
 */
export function clientRequestId(value) {
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

// ---------------------------------------------------------------------------
// Request shape (hp #997)
//
// WHY a request took the route it did is decided by the SHAPE of its body —
// which fields it carries, what routing preferences it states — never by its
// words. Before this, the trace said only which field FIRST cost the direct
// route, so a client `provider` object hiding behind `prompt_cache_retention`
// (and silently dropping the platform Venice exclusion) was invisible.
//
// Same containment rule as the rest of this file. What leaves:
//   - top-level field NAMES (slug-shaped, bounded) — never values;
//   - the model id the caller sent (hp already receives it at /authorize);
//   - counts (messages, tools) and one boolean (any image part);
//   - values of ROUTING directives only, each shape-checked: the `provider`
//     preference object (slugs, enums, booleans), the reasoning knobs,
//     response_format.type, tool_choice mode, cache-retention / service-tier
//     labels.
// What never leaves: message text, system prompts, tool definitions or
// arguments, image/file data, response_format schemas, any free-text value.
// ---------------------------------------------------------------------------

/** OpenRouter model ids, including `~author/x-latest` aliases. */
const MODEL_RE = /^~?[A-Za-z0-9._:/@-]{1,127}$/;
/** A JSON member name worth reporting. Anything else is only counted. */
const FIELD_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,47}$/;
/** Short enum-ish directive values: `high`, `24h`, `json_schema`, `price`. */
const SMALL_LABEL_RE = /^[A-Za-z0-9._-]{1,32}$/;
const MAX_FIELDS = 40;
const MAX_PROVIDER_LIST = 16;
const TOOL_CHOICE_MODES = new Set(['auto', 'none', 'required']);
const PROVIDER_LISTS = ['order', 'only', 'ignore', 'quantizations'];
const PROVIDER_BOOLS = ['allow_fallbacks', 'require_parameters', 'zdr'];

function smallLabel(value) {
  if (typeof value !== 'string') return undefined;
  return SMALL_LABEL_RE.test(value) ? value : undefined;
}

function bool(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Sorted, de-duplicated, bounded list of reportable names; the rest counted. */
function fieldNames(list) {
  const names = new Set();
  let dropped = 0;
  for (const k of Array.isArray(list) ? list : []) {
    if (typeof k === 'string' && FIELD_NAME_RE.test(k) && names.size < MAX_FIELDS) names.add(k);
    else dropped++;
  }
  return { names: [...names].sort(), dropped };
}

/**
 * A `provider` routing-preference object reduced to its allowlisted members.
 * Returns `{ invalid: true }` for a non-object (OpenRouter would reject it,
 * which is itself the answer), undefined when absent.
 */
export function sanitizeProviderPrefs(p) {
  if (p === undefined || p === null) return undefined;
  if (!isPlainObject(p)) return { invalid: true };
  const out = {};
  const { names } = fieldNames(Object.keys(p));
  out.keys = names;
  for (const k of PROVIDER_LISTS) {
    if (!Array.isArray(p[k])) continue;
    out[k] = p[k].map(label).filter(Boolean).slice(0, MAX_PROVIDER_LIST);
  }
  for (const k of PROVIDER_BOOLS) {
    const b = bool(p[k]);
    if (b !== undefined) out[k] = b;
  }
  const sort = smallLabel(typeof p.sort === 'string' ? p.sort : p.sort?.by);
  if (sort) out.sort = sort;
  if (p.data_collection === 'allow' || p.data_collection === 'deny') out.data_collection = p.data_collection;
  return out;
}

/**
 * Enforce every bound on a candidate request shape (the output of
 * describeRequestShape, or anything else — only allowlisted members survive).
 */
export function sanitizeRequestShape(s) {
  if (!isPlainObject(s)) return undefined;
  const out = {};
  if (typeof s.model_requested === 'string' && MODEL_RE.test(s.model_requested)) {
    out.model_requested = s.model_requested;
  }
  const { names, dropped } = fieldNames(s.fields);
  out.fields = names;
  const extraDropped = nonNegInt(s.fields_dropped) ?? 0;
  if (dropped + extraDropped > 0) out.fields_dropped = dropped + extraDropped;
  const nMsg = nonNegInt(s.n_messages);
  if (nMsg !== undefined) out.n_messages = nMsg;
  const nTools = nonNegInt(s.n_tools);
  if (nTools !== undefined) out.n_tools = nTools;
  if (s.has_image === true) out.has_image = true;
  for (const k of ['include_reasoning', 'reasoning_enabled', 'reasoning_exclude', 'stream']) {
    const b = bool(s[k]);
    if (b !== undefined) out[k] = b;
  }
  for (const k of ['reasoning_effort', 'response_format', 'prompt_cache_retention', 'service_tier', 'verbosity']) {
    const v = smallLabel(s[k]);
    if (v) out[k] = v;
  }
  if (typeof s.tool_choice === 'string' && (TOOL_CHOICE_MODES.has(s.tool_choice) || s.tool_choice === 'function')) {
    out.tool_choice = s.tool_choice;
  }
  const pin = sanitizeProviderPrefs(s.provider_in);
  if (pin) out.provider_in = pin;
  const pout = sanitizeProviderPrefs(s.provider_out);
  if (pout) out.provider_out = pout;
  return out;
}

function hasImagePart(messages) {
  for (const m of messages) {
    if (!Array.isArray(m?.content)) continue;
    for (const part of m.content) {
      const t = part?.type;
      if (t === 'image_url' || t === 'input_image' || t === 'image') return true;
    }
  }
  return false;
}

/**
 * Reduce a decrypted CLIENT request body to its routing-relevant shape. Reads
 * only member names, lengths, and routing-directive values — see the header
 * above for the full list. Never throws: a hostile body yields a partial shape.
 * Everything it returns still passes through sanitizeRequestShape at build().
 */
export function describeRequestShape(payload) {
  try {
    if (!isPlainObject(payload)) return undefined;
    const model = typeof payload.model === 'string' ? payload.model : payload.model?.id;
    const reasoning = isPlainObject(payload.reasoning) ? payload.reasoning : undefined;
    const tc = payload.tool_choice;
    return {
      model_requested: model,
      fields: Object.keys(payload),
      n_messages: Array.isArray(payload.messages) ? payload.messages.length : undefined,
      n_tools: Array.isArray(payload.tools) ? payload.tools.length : undefined,
      has_image: Array.isArray(payload.messages) ? hasImagePart(payload.messages) : false,
      stream: payload.stream,
      include_reasoning: payload.include_reasoning,
      reasoning_effort: payload.reasoning_effort ?? reasoning?.effort,
      reasoning_enabled: reasoning?.enabled,
      reasoning_exclude: reasoning?.exclude,
      response_format: payload.response_format?.type,
      prompt_cache_retention: payload.prompt_cache_retention,
      service_tier: payload.service_tier,
      verbosity: payload.verbosity,
      tool_choice: typeof tc === 'string' ? tc : isPlainObject(tc) ? 'function' : undefined,
      provider_in: payload.provider,
    };
  } catch {
    return undefined;
  }
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
  // The two marks the backend derives time-to-first-token and generation speed
  // from, with the same meaning a proxy measuring the same request would give
  // them: the request going out to the upstream, and the first frame that
  // carries generated text. Always present, null when the mark was not reached
  // (a request that never went upstream, a stream with no text, a JSON body).
  out.t_upstream_sent_ms = nonNegInt(obj.t_upstream_sent_ms) ?? null;
  out.t_first_content_ms = nonNegInt(obj.t_first_content_ms) ?? null;
  out.first_token_kind =
    out.t_first_content_ms !== null && FIRST_TOKEN_KIND_SET.has(obj.first_token_kind)
      ? obj.first_token_kind
      : null;
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
  const shape = sanitizeRequestShape(obj.request_shape);
  if (shape) out.request_shape = shape;
  return out;
}

/** The marks the recorder understands; anything else is ignored. */
export const MARKS = Object.freeze([
  'start',
  'authorized',
  'upstreamSent',
  'upstreamHeaders',
  'firstByte',
  'firstToken',
  'end',
]);

/**
 * Per-request recorder. Every method is a no-throw setter; the only place that
 * decides what leaves is `build()`, which routes through `sanitizeTrace`.
 *
 * `mark(name)` records the FIRST occurrence of each mark only, so a stream that
 * writes ten thousand chunks can call `mark('firstByte')` on every one of them
 * without the timing drifting.
 *
 * The default clock is the MONOTONIC `performance.now()`, not `Date.now()`:
 * every exported timing is an interval from `start`, and a wall-clock step
 * (NTP slew, a host clock correction) between two marks would otherwise shrink
 * or stretch it — or clamp it to zero. The values stay integer milliseconds
 * since `start`, so their wire meaning is unchanged.
 *
 * @param {object} [o]
 * @param {() => number} [o.now]  clock (injectable for tests); defaults to performance.now
 */
export function createTraceRecorder({ now = () => performance.now() } = {}) {
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
    first_token_kind: undefined,
    request_shape: undefined,
  };

  function record(name) {
    if (marks[name] !== undefined) return;
    const t = now();
    marks[name] = typeof t === 'number' && Number.isFinite(t) ? t : 0;
  }

  // `firstToken` is taken only through markFirstToken, which also records its
  // kind: a bare mark could not say what the frame carried.
  function mark(name) {
    if (typeof name !== 'string' || !MARKS.includes(name) || name === 'firstToken') return;
    record(name);
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
    /**
     * The first frame carrying generated text arrived, and what it carried.
     * First-write-wins like every mark: the kind belongs to the frame the
     * timing was taken from, so a later call changes neither.
     */
    markFirstToken(kind) {
      if (marks.firstToken !== undefined) return;
      if (typeof kind !== 'string' || !FIRST_TOKEN_KIND_SET.has(kind)) return;
      record('firstToken');
      state.first_token_kind = kind;
    },
    /** Whether the first-token mark is already taken (detection can stop). */
    hasFirstToken() {
      return marks.firstToken !== undefined;
    },
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
     * The client request's routing shape (describeRequestShape). The recorder
     * holds only that reduction, never the body; build() sanitizes it again.
     */
    setRequestShape(shape) {
      state.request_shape = isPlainObject(shape) ? { ...shape } : undefined;
    },
    /** The `provider` object actually placed on the OpenRouter wire. */
    setOrProvider(provider) {
      if (state.request_shape) state.request_shape.provider_out = provider;
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
        t_upstream_sent_ms: since('upstreamSent'),
        t_first_content_ms: since('firstToken'),
        t_total_ms: total,
      });
    },
  };
}
