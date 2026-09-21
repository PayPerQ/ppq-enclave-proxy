/**
 * Local count of the output a chat-completions stream actually delivered.
 *
 * WHY
 * ---
 * Providers price a generation from the usage frame at its natural end. When
 * the client hangs up mid-stream the enclave now cancels the upstream at once
 * (server.mjs, res 'close'): every provider we route to stops generating and
 * billing us at that point (measured 2026-09-21 through OpenRouter for
 * Fireworks, Venice/DeepSeek, Google and Anthropic: 16-18% of the full run
 * billed after a 3 s abort; Fireworks documents "close the connection to stop
 * generation and avoid billing for ungenerated tokens"). But the usage frame
 * then never arrives, and a settle of 0/0 tokens bills the customer nothing
 * for the megabytes they did receive. This counter is what the settle falls
 * back to: the o200k count of the text deltas that went out on the wire.
 *
 * WHAT IS COUNTED
 * ---------------
 * The same chat-completions SSE dialect the extractor sees (dialect
 * translators run before both). Per `data:` line, for every choice delta:
 * `content`, `reasoning` (OpenRouter), `reasoning_content` (Fireworks /
 * DeepSeek wire shape) and `tool_calls[].function.arguments`. Reasoning is
 * counted because providers bill it as output (an aborted Kimi run measured
 * 370 billed tokens with zero content characters delivered).
 *
 * NOT counted: Anthropic thinking (the translator drops thinking_delta — no
 * chat equivalent), so an aborted Anthropic-direct stream is under-counted by
 * its thinking. The usage frame remains the authority whenever it arrives.
 *
 * CONTENT-FREE
 * ------------
 * Text is accumulated only to be tokenized and is dropped by finish(). Nothing
 * here is logged or exported; the module hands back numbers. Accumulation is
 * capped so a runaway stream cannot grow memory without bound: past the cap,
 * bytes are counted by a fixed chars-per-token ratio instead of tokenized.
 */
import { loadTokenizer, TOKENIZE_SLICE_CHARS } from './inputEstimate.mjs';

/** Chars of delivered text kept for exact tokenization; beyond this, estimated. */
export const MAX_COUNTED_CHARS = 2_000_000;
/** Fallback ratio for the overflow beyond the cap (o200k on English prose ~4). */
export const OVERFLOW_CHARS_PER_TOKEN = 4;
/**
 * Longest SSE line kept while waiting for its newline. A real chat chunk is a
 * few hundred bytes; an upstream that never terminates a line would otherwise
 * grow the partial-line buffer without bound (CodeRabbit on #204). Past this,
 * the partial line is dropped and bytes are skipped until the next newline —
 * the count is short by that one chunk, which is the safe direction.
 */
export const MAX_LINE_CHARS = 1_000_000;

function deltaText(delta) {
  if (!delta || typeof delta !== 'object') return '';
  let s = '';
  if (typeof delta.content === 'string') s += delta.content;
  if (typeof delta.reasoning === 'string') s += delta.reasoning;
  if (typeof delta.reasoning_content === 'string') s += delta.reasoning_content;
  if (Array.isArray(delta.tool_calls)) {
    for (const tc of delta.tool_calls) {
      const args = tc?.function?.arguments;
      if (typeof args === 'string') s += args;
    }
  }
  return s;
}

export class OutputCounter {
  constructor() {
    this.buffer = '';
    this.skippingLine = false;
    this.droppedLines = 0;
    this.text = '';
    this.chars = 0;
    this.overflowChars = 0;
    this.decoder = new TextDecoder();
  }

  /** Feed a raw SSE chunk (Buffer or string) in the chat-completions dialect. */
  feed(chunk) {
    let s = typeof chunk === 'string' ? chunk : this.decoder.decode(chunk, { stream: true });
    if (this.skippingLine) {
      // Discarding the rest of an overlong line: resume at its newline.
      const nl = s.indexOf('\n');
      if (nl < 0) return;
      s = s.slice(nl + 1);
      this.skippingLine = false;
    }
    this.buffer += s;
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';
    for (const line of lines) this._line(line);
    if (this.buffer.length > MAX_LINE_CHARS) {
      this.buffer = '';
      this.skippingLine = true;
      this.droppedLines += 1;
    }
  }

  _line(line) {
    if (line.length > MAX_LINE_CHARS) {
      this.droppedLines += 1;
      return;
    }
    if (!line.startsWith('data:')) return;
    const json = line.slice(5).trim();
    if (json === '' || json === '[DONE]') return;
    let c;
    try {
      c = JSON.parse(json);
    } catch {
      return;
    }
    const choices = Array.isArray(c?.choices) ? c.choices : [];
    for (const ch of choices) this._add(deltaText(ch?.delta));
  }

  _add(s) {
    if (!s) return;
    this.chars += s.length;
    const room = MAX_COUNTED_CHARS - this.text.length;
    if (room >= s.length) {
      this.text += s;
    } else {
      if (room > 0) this.text += s.slice(0, room);
      this.overflowChars += s.length - Math.max(room, 0);
    }
  }

  /**
   * Delivered characters and their o200k token count. Tokenizes in slices so a
   * long answer does not block the event loop in one call. Resolves the
   * estimate-by-ratio when the tokenizer is unavailable, never throws.
   */
  async finish() {
    if (this.buffer.trim() !== '') this._line(this.buffer);
    this.buffer = '';
    const text = this.text;
    this.text = '';
    let tokens = 0;
    const countTokens = await loadTokenizer().catch(() => null);
    if (countTokens) {
      for (let i = 0; i < text.length; i += TOKENIZE_SLICE_CHARS) {
        tokens += countTokens(text.slice(i, i + TOKENIZE_SLICE_CHARS));
        if (i % (TOKENIZE_SLICE_CHARS * 32) === 0) await new Promise((r) => setImmediate(r));
      }
    } else {
      tokens = Math.ceil(text.length / OVERFLOW_CHARS_PER_TOKEN);
    }
    tokens += Math.ceil(this.overflowChars / OVERFLOW_CHARS_PER_TOKEN);
    return { chars: this.chars, tokens };
  }
}
