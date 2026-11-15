/**
 * How the upstream ended the answer, read from the stream's STRUCTURE and
 * never from its text (#468).
 *
 * WHY
 * ---
 * A provider that rejects a request after the 200 is on the wire has only
 * the body left to say so: OpenRouter writes an `error` frame into the stream,
 * Vertex answers with a block reason and no candidates, a moderated
 * completion ends with `finish_reason: content_filter`. Until now the trace
 * said `stream_end: clean` for all of these, the settle billed them, and the
 * reason went to the client and nowhere else — which is how 69 Meta policy
 * rejections in two days were invisible until Meta blocked the account.
 *
 * THE CONTAINMENT RULE (trace.mjs)
 * --------------------------------
 * Everything this module returns is an enum from a fixed vocabulary or a
 * shape-validated token: the OpenAI finish reason (closed set), the
 * provider's native finish reason and block reason (token-shaped, no spaces,
 * no punctuation), an HTTP-shaped error code (three digits) and the
 * provider's name (slug). `error.message` — free text the provider wrote,
 * which can quote the request — is never read. Each key is matched only as a
 * real JSON member (`(?<!\\)"key"`): inside a string value the quote is
 * escaped, so a prompt that spells `"finish_reason": "error"` is not a match.
 *
 * Fed the upstream's OWN frames, before translation: a translator maps an
 * Anthropic `stop_reason: refusal` or a Responses `incomplete_details.reason:
 * content_filter` to a plain `stop` for the client, and its own error frames
 * carry a 502 that is not the provider's verdict. On the raw frames the
 * provider's word survives: `stop_reason` and `incomplete_details.reason` are
 * read alongside the chat-completions fields. A non-streaming JSON body is
 * one line. Lines longer than MAX_LINE_CHARS are inspected only on their
 * tail, where the terminal fields of a JSON body sit; a content delta that
 * long carries no outcome.
 */

/** OpenAI-style finish reasons the trace reports; anything else is dropped. */
export const FINISH_REASONS = Object.freeze([
  'stop',
  'length',
  'content_filter',
  'tool_calls',
  'function_call',
  'error',
]);
const FINISH_REASON_SET = new Set(FINISH_REASONS);

/** A provider's own enum value: `STOP`, `PROHIBITED_CONTENT`, `end_turn`, `completed`. */
export const OUTCOME_TOKEN_RE = /^[A-Za-z_]{1,40}$/;
/** A provider slug as the trace carries it; the same shape on the hp side. */
export const PROVIDER_SLUG_RE = /^[a-z0-9._-]{1,40}$/;
/** How far past `"error": {` the code and provider are looked for: the object, not the line. */
const ERROR_SPAN_CHARS = 1024;

const MAX_LINE_CHARS = 64 * 1024;
const TAIL_CHARS = 8 * 1024;
const MAX_PENDING_CHARS = 256 * 1024;

const FINISH_RE = /(?<!\\)"finish_reason"\s*:\s*"([a-z_]{1,40})"/g;
/** Anthropic's terminal field on its own frames: end_turn, max_tokens, stop_sequence, tool_use, refusal. */
const STOP_REASON_RE = /(?<!\\)"stop_reason"\s*:\s*"([a-z_]{1,40})"/g;
/** Responses API: `"incomplete_details":{"reason":"content_filter"}` on the terminal object. */
const INCOMPLETE_RE = /(?<!\\)"incomplete_details"\s*:\s*\{\s*"reason"\s*:\s*"([a-z_]{1,40})"/g;
const NATIVE_FINISH_RE = /(?<!\\)"native_finish_reason"\s*:\s*"([A-Za-z_]{1,40})"/g;
const BLOCK_REASON_RE = /(?<!\\)"(?:block_reason|blockReason)"\s*:\s*"([A-Za-z_]{1,40})"/g;
const ERROR_OBJECT_RE = /(?<!\\)"error"\s*:\s*\{/;
const ERROR_CODE_RE = /(?<!\\)"code"\s*:\s*"?(\d{3})"?/;
const PROVIDER_NAME_RE = /(?<!\\)"provider_name"\s*:\s*"([A-Za-z0-9 ._-]{1,40})"/;

function lastMatch(re, text) {
  let m;
  let last;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) last = m[1];
  return last;
}

/**
 * The text of the JSON object that opens at `text[start]` (a `{`), up to its
 * matching brace, string-aware so a brace inside a string value does not end
 * it; at most ERROR_SPAN_CHARS. The error object's own members are read from
 * this span and nothing outside it — a `code` on a later sibling is not the
 * error's code.
 */
export function objectSpan(text, start) {
  let depth = 0;
  let inString = false;
  const end = Math.min(text.length, start + ERROR_SPAN_CHARS);
  for (let i = start; i < end; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === '\\') i++;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return text.slice(start, i + 1);
  }
  return text.slice(start, end);
}

/** `Google AI Studio` → `google-ai-studio`; anything outside the slug shape is dropped. */
export function providerSlug(name) {
  if (typeof name !== 'string') return undefined;
  const slug = name.trim().toLowerCase().replace(/\s+/g, '-');
  return PROVIDER_SLUG_RE.test(slug) ? slug : undefined;
}

/**
 * Read the outcome fields from one frame line. Pure; returns the members it
 * found (last occurrence wins within the line), nothing for a content delta.
 */
export function readOutcomeLine(line) {
  const text = line.length > MAX_LINE_CHARS ? line.slice(-TAIL_CHARS) : line;
  const out = {};
  const finish = lastMatch(FINISH_RE, text);
  if (finish !== undefined && FINISH_REASON_SET.has(finish)) out.finish_reason = finish;
  const native = lastMatch(NATIVE_FINISH_RE, text) ?? lastMatch(STOP_REASON_RE, text);
  if (native !== undefined && OUTCOME_TOKEN_RE.test(native)) out.native_finish_reason = native;
  // A Responses object that ended on the provider's filter: the chat-shaped
  // field the client sees is `stop`, the provider's reason is here.
  const incomplete = lastMatch(INCOMPLETE_RE, text);
  if (incomplete === 'content_filter') out.finish_reason = 'content_filter';
  const block = lastMatch(BLOCK_REASON_RE, text);
  if (block !== undefined && OUTCOME_TOKEN_RE.test(block)) out.block_reason = block;
  const errAt = text.search(ERROR_OBJECT_RE);
  if (errAt !== -1) {
    const after = objectSpan(text, text.indexOf('{', errAt));
    const code = after.match(ERROR_CODE_RE);
    if (code) out.error_code = Number(code[1]);
    const provider = providerSlug(after.match(PROVIDER_NAME_RE)?.[1]);
    if (provider) out.error_provider = provider;
  }
  return out;
}

/**
 * Line-buffering accumulator over the upstream's frames. `feed` takes each
 * chunk; `finish` flushes a trailing partial line and returns the outcome, or
 * undefined when no frame carried one. Later frames override earlier ones
 * member by member: the terminal chunk's finish reason is the one that counts.
 */
export class UpstreamOutcomeDetector {
  constructor() {
    this.pending = '';
    this.decoder = new TextDecoder();
    this.state = {};
    this.gaveUp = false;
  }

  _line(line) {
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (line.length === 0) return;
    Object.assign(this.state, readOutcomeLine(line));
  }

  /** @param {Uint8Array|string} chunk */
  feed(chunk) {
    if (this.gaveUp) return;
    const text = typeof chunk === 'string' ? chunk : this.decoder.decode(chunk, { stream: true });
    let start = 0;
    let nl;
    while ((nl = text.indexOf('\n', start)) !== -1) {
      this._line(this.pending + text.slice(start, nl));
      this.pending = '';
      start = nl + 1;
    }
    this.pending += text.slice(start);
    if (this.pending.length > MAX_PENDING_CHARS) {
      // A single line past the bound is a content delta or a JSON body we
      // will read on its tail at finish; keep only that tail.
      this.pending = this.pending.slice(-TAIL_CHARS);
    }
  }

  /** @returns {object|undefined} the outcome members seen, or undefined when none. */
  finish() {
    if (this.pending.length > 0) {
      this._line(this.pending);
      this.pending = '';
    }
    this.gaveUp = true;
    return Object.keys(this.state).length > 0 ? { ...this.state } : undefined;
  }
}
