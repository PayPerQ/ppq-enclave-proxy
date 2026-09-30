/**
 * What counts as the first generated token of a streamed answer.
 *
 * "Time to first token" is only a number anyone can act on if every request
 * means the same thing by "token". A stream says a lot before it says anything:
 * SSE keep-alive comments, a role-only delta announcing the assistant, empty
 * deltas, metadata and usage frames. Counting any of those would measure when
 * the provider started TALKING, not when the user started READING.
 *
 * So a frame counts only when it carries non-empty generated text:
 *  - answer text → 'content'
 *  - reasoning the model streams before answering → 'reasoning'
 *
 * Content wins when a delta carries both: the visible answer is what the user
 * is waiting for.
 *
 * PARITY: the accepted shapes intentionally mirror, exactly, how the backend
 * measures the same interval on requests it proxies itself — no more, no
 * fewer. The value of this mark is that time-to-first-token means the same
 * thing whichever route served the request, so a shape the other side does
 * not count (tool calls, tool-argument deltas, raw reasoning-text events) is
 * deliberately NOT counted here either, even where it would be defensible on
 * its own. Widen both sides together or neither.
 *
 * The detector runs on the UPSTREAM's own frames, before any translation or
 * rewrite, so three dialects reach it:
 *  - chat completions — `choices[].delta.content` / `.reasoning` /
 *    `.reasoning_content`
 *  - Anthropic Messages — `content_block_delta` with `text_delta` /
 *    `thinking_delta`
 *  - OpenAI Responses — `response.output_text.delta` /
 *    `response.reasoning_summary_text.delta`
 *
 * CONTAINMENT: this only ever returns one of two enum values. Nothing from a
 * frame is kept, logged or returned; the frame is parsed to test for
 * non-emptiness and dropped.
 *
 * COST: the parse runs only until the first token is found. After that
 * `FirstTokenDetector.feed` returns at its first statement, so the rest of the
 * stream pays one boolean test per chunk.
 */

/** Longest partial line held while looking; beyond it detection gives up (null). */
const MAX_PENDING_CHARS = 1024 * 1024;

function nonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

/** Choices are read in order; the first delta that carries text decides. */
function chatKind(choices) {
  for (const choice of choices) {
    const delta = choice && typeof choice === 'object' ? choice.delta : undefined;
    if (!delta || typeof delta !== 'object') continue;
    if (nonEmptyString(delta.content)) return 'content';
    if (nonEmptyString(delta.reasoning) || nonEmptyString(delta.reasoning_content)) return 'reasoning';
  }
  return null;
}

function anthropicKind(frame) {
  const d = frame.delta;
  if (!d || typeof d !== 'object') return null;
  if (d.type === 'text_delta' && nonEmptyString(d.text)) return 'content';
  if (d.type === 'thinking_delta' && nonEmptyString(d.thinking)) return 'reasoning';
  return null;
}

/**
 * The kind of generated output one SSE line carries, or null. Pure.
 * @param {string} line one SSE line, without its line terminator
 * @returns {'content'|'reasoning'|null}
 */
export function detectFirstTokenKind(line) {
  if (typeof line !== 'string' || !line.startsWith('data:')) return null;
  const payload = line.slice(5).trim();
  if (payload === '' || payload === '[DONE]' || payload[0] !== '{') return null;
  let frame;
  try {
    frame = JSON.parse(payload);
  } catch {
    return null; // a frame that is not JSON carries no token we can vouch for
  }
  if (!frame || typeof frame !== 'object') return null;

  if (Array.isArray(frame.choices) && frame.choices.length > 0) return chatKind(frame.choices);

  const type = frame.type;
  if (type === 'content_block_delta') return anthropicKind(frame);
  if (type === 'response.output_text.delta') return nonEmptyString(frame.delta) ? 'content' : null;
  if (type === 'response.reasoning_summary_text.delta') {
    return nonEmptyString(frame.delta) ? 'reasoning' : null;
  }
  return null;
}

/**
 * Line-buffering wrapper for a byte stream. `feed` returns the kind exactly
 * once — on the chunk that completes the first token-bearing line — and null
 * otherwise; after that (or after giving up) it does no work at all.
 */
export class FirstTokenDetector {
  constructor() {
    this.done = false;
    this.pending = '';
    this.decoder = new TextDecoder();
  }

  /** @param {Uint8Array} chunk @returns {'content'|'reasoning'|null} */
  feed(chunk) {
    if (this.done) return null;
    const text = this.decoder.decode(chunk, { stream: true });
    let start = 0;
    let nl;
    while ((nl = text.indexOf('\n', start)) !== -1) {
      let line = this.pending + text.slice(start, nl);
      this.pending = '';
      start = nl + 1;
      if (line.endsWith('\r')) line = line.slice(0, -1);
      const kind = detectFirstTokenKind(line);
      if (kind) {
        this.stop();
        return kind;
      }
    }
    this.pending += text.slice(start);
    if (this.pending.length > MAX_PENDING_CHARS) this.stop();
    return null;
  }

  /** Stop looking and release what was held. */
  stop() {
    this.done = true;
    this.pending = '';
  }
}
