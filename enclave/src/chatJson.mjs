/**
 * One chat.completion object from a chat-completions event stream, for a
 * caller that did not ask for a stream (ppq-enclave-proxy #411).
 *
 * Why this exists. A direct provider's JSON answer (Tinfoil, Fireworks,
 * Foundry, Vertex, Venice, Anthropic) sends nothing on the wire until the
 * whole generation is done; the enclave relayed that silence to the client.
 * The NLB in front of the enclave drops a TCP flow that carries no bytes for
 * 350 s, silently to the enclave, so a non-streaming request whose answer
 * took longer than that was generated in full, billed in full from the
 * provider's usage, and delivered to nobody (Chatwoot 2171, 2026-11-05: eight
 * answers of 9-22 minutes, $10.76 for zero bytes). OpenRouter's own JSON
 * answers survive the same wait because OpenRouter starts emitting bytes
 * within seconds. So the enclave now asks every direct upstream for a stream,
 * runs it through the pipeline every streamed answer goes through, keeps the
 * client's connection alive with whitespace (valid ahead of a JSON body) and
 * writes the assembled object at the end. The upstream status is known from
 * its first frame, so the client's status is the upstream's; a client that
 * hangs up mid-generation is seen at once (the flow is alive) and the upstream
 * is cancelled like any other stream's.
 *
 * What is merged, by the OpenAI chat-completions chunk shape as OpenRouter and
 * every direct dialect translator emit it: per choice index, the delta's
 * string fields are concatenated (content, reasoning, reasoning_content,
 * refusal), tool calls are merged by their own `index` with `arguments`
 * concatenated, `reasoning_details` entries that continue the previous entry
 * (same type / index / format / id) have their text joined, other arrays are
 * appended; `finish_reason` is the last one stated; `usage` is the last usage
 * object on the stream (the include_usage frame); top-level identity fields
 * (id, created, model, provider, system_fingerprint, ...) are the first seen;
 * an in-band `error` member is kept, as it would be on a JSON answer.
 *
 * Bounded: everything held is counted against MAX_ASSEMBLED_CHARS — delta text,
 * tool arguments, and the serialized size of every array or object merged
 * (annotations, logprobs, citations, reasoning entries) — and one `data:` line
 * longer than MAX_LINE_CHARS is dropped rather than buffered (cost.mjs and
 * outputCount.mjs do the same). Past the bound the answer is an error object
 * rather than the enclave's memory, and `failed` says so, so the handler can
 * settle it as a failure and not as a clean answer. Content-free: nothing here
 * logs or reports what it holds.
 */

/** Keepalive cadence while a non-streaming answer is still generating. */
export const DEFAULT_KEEPALIVE_MS = 20_000;
/** Bounds on the env override (tests set it to tens of milliseconds). */
export const MIN_KEEPALIVE_MS = 10;
export const MAX_KEEPALIVE_MS = 60_000;

/**
 * The keepalive interval, from an env override or the default. Idle timeouts
 * on the path are hundreds of seconds (NLB 350 s, AWS NAT 350 s, Cloudflare
 * 100 s, ALB 60 s), so the default sits well under the shortest of them.
 *
 * @param {string|undefined} raw  e.g. process.env.NONSTREAM_KEEPALIVE_MS
 * @returns {number}
 */
export function keepaliveIntervalMs(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_KEEPALIVE_MS;
  return Math.min(MAX_KEEPALIVE_MS, Math.max(MIN_KEEPALIVE_MS, Math.floor(n)));
}

/** The byte written as a keepalive: insignificant whitespace ahead of JSON. */
export const KEEPALIVE_BYTES = Buffer.from(' ', 'utf8');

/** Characters of assembled text (all string fields, all choices) held at most. */
export const MAX_ASSEMBLED_CHARS = 16 * 1024 * 1024;

/** One `data:` payload longer than this is not parsed (cost.mjs has the same bound). */
export const MAX_LINE_CHARS = 1_000_000;

/**
 * What a new choice or tool-call record costs against the text bound. The
 * records themselves are small, but a stream of frames with distinct indexes
 * and empty deltas would otherwise grow `choices` (or a message's tool_calls)
 * without moving `chars` at all.
 */
export const RECORD_CHARS = 64;

/** Delta members that are text and concatenate. */
const TEXT_FIELDS = new Set(['content', 'reasoning', 'reasoning_content', 'refusal']);

/** Top-level chunk members that are not copied onto the assembled object as-is. */
const CHUNK_ONLY_FIELDS = new Set(['object', 'choices', 'usage', 'error']);

function isRecord(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * A member name that must never be merged: a parsed frame can carry an own
 * `__proto__` (or `constructor` / `prototype`), and assigning through it
 * would reach Object.prototype — every plain object in the process,
 * including hp's parsed answers. Skipped wherever a frame's keys are walked.
 */
function unsafeKey(key) {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

/**
 * Whether `entry` continues `prev` in a `reasoning_details` array: the same
 * kind of entry at the same position, so their text is one text.
 */
function continuesDetail(prev, entry) {
  if (!isRecord(prev) || !isRecord(entry)) return false;
  return (
    prev.type === entry.type &&
    (prev.index ?? 0) === (entry.index ?? 0) &&
    prev.format === entry.format &&
    prev.id === entry.id
  );
}

export class ChatSseToJson {
  /**
   * @param {object} [o]
   * @param {number} [o.maxChars]  text bound; past it finish() is an error object
   */
  constructor({ maxChars = MAX_ASSEMBLED_CHARS } = {}) {
    this.maxChars = maxChars;
    this.decoder = new TextDecoder('utf-8');
    this.carry = '';
    this.dataLines = [];
    /** @type {null | Record<string, unknown>} */
    this.acc = null;
    /** @type {Map<number, Record<string, any>>} */
    this.choices = new Map();
    this.usage = undefined;
    this.error = undefined;
    this.chars = 0;
    this.overflow = false;
    this.frames = 0;
    this.unparsed = 0;
    /** A line past MAX_LINE_CHARS is being discarded up to its newline. */
    this.skippingLine = false;
    /** Characters of `data:` lines held for the event that has not ended yet. */
    this.pendingChars = 0;
    /** An event whose data lines passed MAX_LINE_CHARS is being discarded up to its blank line. */
    this.skippingEvent = false;
  }

  /**
   * Whether finish() is an error object instead of a completion: the bound was
   * passed, or no choice ever came (an error frame alone, or nothing).
   */
  get failed() {
    return this.overflow || this.choices.size === 0;
  }

  /**
   * Whether the stream carried an in-band `error` frame. Beside a completion
   * it is kept on the answer (`result().error`) and `failed` stays false — the
   * streamed client would have received both — but the row is the upstream's
   * failure, not a clean one; the handler reads this to say so.
   */
  get hasError() {
    return this.error !== undefined;
  }

  /** Why, when `failed`: 'overflow' | 'no_completion' | null. */
  get failureReason() {
    if (this.overflow) return 'overflow';
    if (this.choices.size === 0) return 'no_completion';
    return null;
  }

  /**
   * Bytes of the event stream as they would have gone to a streaming client
   * (after the rewriter: public model slug, restored text).
   *
   * @param {Buffer} buf
   */
  feed(buf) {
    if (!buf || buf.length === 0 || this.overflow) return;
    this.carry += this.decoder.decode(buf, { stream: true });
    this._drainLines(false);
    // A line that has not ended within MAX_LINE_CHARS is not held any longer:
    // it is dropped up to its newline (outputCount.mjs's rule), never buffered.
    if (!this.skippingLine && this.carry.length > MAX_LINE_CHARS) {
      this.carry = '';
      this.dataLines = [];
      this.skippingLine = true;
      this.unparsed += 1;
    }
  }

  /**
   * The assembled chat.completion body, as bytes, once the stream has ended.
   * An error object (status is already on the wire) when nothing usable came.
   *
   * @returns {Buffer}
   */
  finish() {
    this.carry += this.decoder.decode();
    this._drainLines(true);
    return Buffer.from(JSON.stringify(this.result()), 'utf8');
  }

  /** The assembled object (finish() serialises this). */
  result() {
    if (this.overflow) {
      return { error: { message: 'upstream response too large to assemble', code: 502 } };
    }
    if (!this.acc || this.choices.size === 0) {
      // No choice ever came: an error frame alone is that error, as a JSON
      // error answer would be; nothing at all is the enclave's own 502.
      return this.error
        ? { error: this.error }
        : { error: { message: 'upstream stream carried no completion', code: 502 } };
    }
    const out = { ...this.acc, object: 'chat.completion' };
    out.choices = [...this.choices.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([, c]) => {
        // The SSE translators open every message with an empty content delta;
        // a tool-call answer with no text is `content: null` in the
        // chat.completion shape (as ResponsesJsonToChat already states it).
        const m = c.message;
        if (m.content === '' && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) m.content = null;
        return c;
      });
    if (this.usage !== undefined) out.usage = this.usage;
    if (this.error !== undefined) out.error = this.error;
    return out;
  }

  _drainLines(final) {
    let start = 0;
    for (;;) {
      const nl = this.carry.indexOf('\n', start);
      if (nl === -1) break;
      let line = this.carry.slice(start, nl);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      start = nl + 1;
      if (this.skippingLine) {
        // The rest of the over-long line; the event it belonged to is void.
        this.skippingLine = false;
        continue;
      }
      this._line(line);
      if (this.overflow) break;
    }
    this.carry = this.carry.slice(start);
    if (this.skippingLine) this.carry = '';
    if (final && !this.overflow) {
      if (!this.skippingLine && this.carry.length > 0) this._line(this.carry.replace(/\r$/, ''));
      this.carry = '';
      this._event();
    }
  }

  _line(line) {
    if (line === '') {
      // The blank line ends an event — or the one being discarded.
      if (this.skippingEvent) {
        this.skippingEvent = false;
        return;
      }
      return this._event();
    }
    if (this.skippingEvent) return;
    if (line.startsWith(':')) return; // comment (the routing receipt rides here)
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    if (field !== 'data') return; // event:/id:/retry: carry nothing here
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    // Many short `data:` lines with no blank line between them are one event
    // that never ends: bounded here, before they are held, by the same
    // MAX_LINE_CHARS the joined payload is checked against.
    this.pendingChars += value.length + 1;
    if (this.pendingChars > MAX_LINE_CHARS) {
      this.dataLines = [];
      this.pendingChars = 0;
      this.skippingEvent = true;
      this.unparsed += 1;
      return;
    }
    this.dataLines.push(value);
  }

  _event() {
    this.pendingChars = 0;
    if (this.dataLines.length === 0) return;
    const data = this.dataLines.join('\n');
    this.dataLines = [];
    if (data === '[DONE]') return;
    if (data.length > MAX_LINE_CHARS) {
      this.unparsed += 1;
      return;
    }
    let chunk;
    try {
      chunk = JSON.parse(data);
    } catch {
      this.unparsed += 1;
      return;
    }
    if (!isRecord(chunk)) {
      this.unparsed += 1;
      return;
    }
    this.frames += 1;
    this._merge(chunk);
  }

  _count(text) {
    this._charge(text.length);
  }

  _charge(chars) {
    this.chars += chars;
    if (this.chars > this.maxChars) this.overflow = true;
  }

  /** An array or object kept whole counts by its serialized size. */
  _countValue(value) {
    try {
      this._count(JSON.stringify(value) ?? '');
    } catch {
      this.overflow = true;
    }
  }

  _merge(chunk) {
    if (isRecord(chunk.error)) this.error = chunk.error;
    if (!this.acc) this.acc = {};
    for (const [key, value] of Object.entries(chunk)) {
      if (unsafeKey(key) || CHUNK_ONLY_FIELDS.has(key) || value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        // Top-level arrays (OpenRouter `citations`) accumulate across chunks.
        const have = Array.isArray(this.acc[key]) ? this.acc[key] : [];
        for (const item of value) {
          if (have.includes(item)) continue;
          have.push(item);
          this._countValue(item);
        }
        this.acc[key] = have;
        continue;
      }
      if (this.acc[key] === undefined) {
        this.acc[key] = value; // identity: first wins
        if (typeof value === 'object') this._countValue(value);
        else if (typeof value === 'string') this._count(value);
      }
    }
    if (isRecord(chunk.usage)) {
      this.usage = chunk.usage;
      this._countValue(chunk.usage);
    }
    if (isRecord(chunk.error)) this._countValue(chunk.error);
    if (!Array.isArray(chunk.choices)) return;
    for (const c of chunk.choices) {
      if (!isRecord(c)) continue;
      const index = Number.isInteger(c.index) && c.index >= 0 ? c.index : 0;
      let choice = this.choices.get(index);
      if (!choice) {
        choice = { index, message: { role: 'assistant', content: null }, finish_reason: null, logprobs: null };
        this.choices.set(index, choice);
        this._charge(RECORD_CHARS);
      }
      if (c.finish_reason !== undefined && c.finish_reason !== null) choice.finish_reason = c.finish_reason;
      if (c.native_finish_reason !== undefined && c.native_finish_reason !== null) {
        choice.native_finish_reason = c.native_finish_reason;
      }
      if (isRecord(c.logprobs)) this._mergeLogprobs(choice, c.logprobs);
      if (isRecord(c.delta)) this._mergeDelta(choice.message, c.delta);
      // A chunk that carries a whole `message` (some providers' final frame) is
      // merged the same way: its strings append to what the deltas built.
      if (isRecord(c.message)) this._mergeDelta(choice.message, c.message);
      if (this.overflow) return;
    }
  }

  _mergeLogprobs(choice, logprobs) {
    const have = isRecord(choice.logprobs) ? choice.logprobs : (choice.logprobs = {});
    for (const [key, value] of Object.entries(logprobs)) {
      if (unsafeKey(key)) continue;
      if (Array.isArray(value)) {
        have[key] = Array.isArray(have[key]) ? have[key].concat(value) : value.slice();
        this._countValue(value);
      } else if (value !== null && value !== undefined && have[key] === undefined) {
        have[key] = value;
        this._countValue(value);
      }
    }
  }

  _mergeDelta(message, delta) {
    for (const [key, value] of Object.entries(delta)) {
      if (unsafeKey(key) || value === undefined || value === null) continue;
      if (key === 'role') {
        if (typeof value === 'string') message.role = value;
        continue;
      }
      if (key === 'tool_calls') {
        if (Array.isArray(value)) this._mergeToolCalls(message, value);
        continue;
      }
      if (key === 'reasoning_details') {
        if (Array.isArray(value)) this._mergeReasoningDetails(message, value);
        continue;
      }
      if (typeof value === 'string' && (TEXT_FIELDS.has(key) || typeof message[key] === 'string')) {
        message[key] = (typeof message[key] === 'string' ? message[key] : '') + value;
        this._count(value);
        continue;
      }
      if (Array.isArray(value)) {
        // annotations, images, and any other list: appended in order.
        message[key] = Array.isArray(message[key]) ? message[key].concat(value) : value.slice();
        this._countValue(value);
        continue;
      }
      if (isRecord(value) && isRecord(message[key])) {
        Object.assign(message[key], value);
        this._countValue(value);
        continue;
      }
      message[key] = value;
      this._countValue(value);
    }
  }

  _mergeToolCalls(message, calls) {
    const list = Array.isArray(message.tool_calls) ? message.tool_calls : (message.tool_calls = []);
    for (let position = 0; position < calls.length; position++) {
      const call = calls[position];
      if (!isRecord(call)) continue;
      const index = Number.isInteger(call.index) && call.index >= 0 ? call.index : list.length;
      let have = list.find((t) => t.index === index);
      if (!have) {
        have = { index, id: undefined, type: 'function', function: { name: '', arguments: '' } };
        list.push(have);
        this._charge(RECORD_CHARS);
      }
      if (typeof call.id === 'string' && call.id !== '') {
        have.id = call.id;
        this._count(call.id);
      }
      if (typeof call.type === 'string' && call.type !== '') {
        have.type = call.type;
        this._count(call.type);
      }
      if (isRecord(call.function)) {
        const fn = call.function;
        if (typeof fn.name === 'string' && fn.name !== '') {
          have.function.name += fn.name;
          this._count(fn.name);
        }
        if (typeof fn.arguments === 'string' && fn.arguments !== '') {
          have.function.arguments += fn.arguments;
          this._count(fn.arguments);
        }
      }
    }
    list.sort((a, b) => a.index - b.index);
  }

  _mergeReasoningDetails(message, entries) {
    const list = Array.isArray(message.reasoning_details)
      ? message.reasoning_details
      : (message.reasoning_details = []);
    for (const entry of entries) {
      if (!isRecord(entry)) continue;
      const prev = list.length > 0 ? list[list.length - 1] : null;
      if (prev && continuesDetail(prev, entry)) {
        for (const key of ['text', 'summary', 'data']) {
          if (typeof entry[key] === 'string') {
            prev[key] = (typeof prev[key] === 'string' ? prev[key] : '') + entry[key];
            this._count(entry[key]);
          }
        }
        for (const [key, value] of Object.entries(entry)) {
          if (unsafeKey(key) || key === 'text' || key === 'summary' || key === 'data') continue;
          if (prev[key] === undefined && value !== null && value !== undefined) prev[key] = value;
        }
        continue;
      }
      const copy = {};
      for (const [key, value] of Object.entries(entry)) {
        if (!unsafeKey(key)) copy[key] = value;
      }
      this._countValue(copy);
      list.push(copy);
    }
  }
}
