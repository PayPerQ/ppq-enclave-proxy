/**
 * Reasoning field parity for the Fireworks direct path (#256).
 *
 * WHY
 * ---
 * Fireworks returns a reasoning model's thinking under `reasoning_content`
 * (the DeepSeek/Moonshot wire shape). OpenRouter relays the same thinking as
 * `reasoning` plus a `reasoning_details` array. api.ppq.ai promises the
 * OpenRouter shape, and an OpenRouter-native client reads ONLY those two
 * members: on a direct turn it shows nothing, and it has nothing to replay
 * on the next turn. Kimi K3 then stops thinking on tool-loop continuation
 * turns (measured 2026-09-30: 0 reasoning tokens on 7/7 continuation turns
 * with no replay; thinking resumed with replay). Which route a turn takes
 * varies per request, so the same user watches reasoning appear and vanish.
 *
 * WHAT
 * ----
 * On a Fireworks-direct response, every chat chunk (stream delta) or message
 * (non-streaming body) that carries `reasoning_content` gets `reasoning` and
 * `reasoning_details` mirrored beside it. `reasoning_content` is kept, so a
 * Fireworks-shaped client (opencode, the Vercel AI SDK) is unaffected.
 *
 * FAIL-OPEN
 * ---------
 * Only a `data: {…}` line that parses as a chat chunk AND names
 * `reasoning_content` is re-serialized; every other line passes through
 * unchanged — comments, `[DONE]`, error frames, and any line longer than
 * MAX_LINE_CHARS. (Like the rewriter in rebrand.mjs, the stream is decoded
 * and re-encoded as UTF-8, so "unchanged" holds for valid UTF-8, which is
 * what every upstream sends.) A non-streaming body is buffered for one
 * rewrite at the end; past MAX_JSON_BODY_CHARS it is flushed raw and the
 * rest passes through. horse-power carries the same logic in
 * utils/reasoningMirrorStream.ts; hp's enclaveReasoningMirrorConformance
 * test holds the two equal.
 *
 * CONTENT-FREE
 * ------------
 * Text is parsed only to be re-emitted to the same client. Nothing is
 * retained past feed()/finish(), logged, or exported.
 */

/** Longest SSE line rewritten; a longer one passes through raw. */
export const MAX_LINE_CHARS = 1_000_000;
/** Largest non-streaming body rewritten; a larger one passes through raw. */
export const MAX_JSON_BODY_CHARS = 16_000_000;

/**
 * Mirror `reasoning_content` on one delta or message object, in place.
 * Never overwrites a `reasoning` or `reasoning_details` the upstream set.
 * Returns true when something changed.
 */
export function mirrorReasoningInto(part) {
  if (!part || typeof part !== 'object' || Array.isArray(part)) return false;
  const text = part.reasoning_content;
  if (typeof text !== 'string') return false;
  let changed = false;
  if (part.reasoning === undefined || part.reasoning === null) {
    part.reasoning = text;
    changed = true;
  }
  if (text !== '' && part.reasoning_details === undefined) {
    part.reasoning_details = [{ type: 'reasoning.text', text, format: 'unknown', index: 0 }];
    changed = true;
  }
  return changed;
}

/** Mirror across every choice of a parsed chat chunk or body. */
export function mirrorReasoningInChunk(obj) {
  const choices = obj?.choices;
  if (!Array.isArray(choices)) return false;
  let changed = false;
  for (const choice of choices) {
    if (!choice || typeof choice !== 'object') continue;
    if (mirrorReasoningInto(choice.delta)) changed = true;
    if (mirrorReasoningInto(choice.message)) changed = true;
  }
  return changed;
}

/**
 * Rewrite one SSE line (no trailing newline). Returns the input string itself
 * whenever there is nothing to do, so a caller can cheaply detect a no-op.
 */
export function mirrorReasoningLine(line) {
  if (line.length > MAX_LINE_CHARS || !line.startsWith('data:')) return line;
  const payload = line.slice(5).trim();
  if (!payload.startsWith('{') || !payload.includes('reasoning_content')) return line;
  let obj;
  try {
    obj = JSON.parse(payload);
  } catch {
    return line;
  }
  if (!mirrorReasoningInChunk(obj)) return line;
  return `data: ${JSON.stringify(obj)}`;
}

/** Rewrite a whole non-streaming JSON body; the input itself when a no-op. */
export function mirrorReasoningJson(text) {
  if (text.length > MAX_JSON_BODY_CHARS || !text.includes('reasoning_content')) return text;
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return text;
  }
  if (!mirrorReasoningInChunk(obj)) return text;
  return JSON.stringify(obj);
}

/**
 * Chunked rewriter for one response. `sse: true` works line by line and
 * forwards each complete line as it arrives; `sse: false` holds the body for
 * a single rewrite in finish().
 */
export class ReasoningMirror {
  constructor({ sse }) {
    this.sse = sse === true;
    this.buffer = '';
    this.skippingLine = false;
    this.passthrough = false;
    this.decoder = new TextDecoder();
  }

  /** Feed a response chunk; returns the bytes safe to forward now. */
  feed(chunk) {
    const s = typeof chunk === 'string' ? chunk : this.decoder.decode(chunk, { stream: true });
    if (this.passthrough) return Buffer.from(s, 'utf8');
    if (!this.sse) {
      this.buffer += s;
      if (this.buffer.length > MAX_JSON_BODY_CHARS) {
        // Too big to rewrite: release what is held and stop buffering.
        const out = Buffer.from(this.buffer, 'utf8');
        this.buffer = '';
        this.passthrough = true;
        return out;
      }
      return Buffer.alloc(0);
    }
    return Buffer.from(this._feedSse(s), 'utf8');
  }

  _feedSse(s) {
    let out = '';
    let rest = s;
    if (this.skippingLine) {
      // The rest of an overlong line goes out raw; resume at its newline.
      const nl = rest.indexOf('\n');
      if (nl < 0) return rest;
      out += rest.slice(0, nl + 1);
      rest = rest.slice(nl + 1);
      this.skippingLine = false;
    }
    this.buffer += rest;
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';
    for (const line of lines) out += `${this._line(line)}\n`;
    if (this.buffer.length > MAX_LINE_CHARS) {
      out += this.buffer;
      this.buffer = '';
      this.skippingLine = true;
    }
    return out;
  }

  _line(line) {
    // Preserve a CRLF terminator exactly.
    if (line.endsWith('\r')) return `${mirrorReasoningLine(line.slice(0, -1))}\r`;
    return mirrorReasoningLine(line);
  }

  /** Flush at end of stream. */
  finish() {
    const tail = this.decoder.decode();
    if (this.passthrough) return Buffer.from(tail, 'utf8');
    if (!this.sse) {
      const body = this.buffer + tail;
      this.buffer = '';
      return Buffer.from(mirrorReasoningJson(body), 'utf8');
    }
    let out = this.skippingLine ? tail : this._feedSse(tail);
    if (this.buffer !== '') {
      // A final line with no newline (never the case for well-formed SSE).
      out += this._line(this.buffer);
      this.buffer = '';
    }
    return Buffer.from(out, 'utf8');
  }
}
