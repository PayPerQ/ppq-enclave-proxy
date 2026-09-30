/**
 * What counts as the first generated token of a streamed answer.
 *
 * "Time to first token" is only a number anyone can act on if every request
 * means the same thing by "token". A stream says a lot before it says anything:
 * SSE keep-alive comments, a role-only delta announcing the assistant, empty
 * deltas, metadata and usage frames. Counting any of those would measure when
 * the provider started TALKING, not when the user started READING.
 *
 * So a frame counts only when it carries non-empty generated output:
 *  - answer text, or a tool call (the model's answer can be a call) → 'content'
 *  - reasoning the model streams before answering → 'reasoning'
 *
 * Content wins when a frame carries both: the visible answer is what the user
 * is waiting for.
 *
 * The detector runs on the UPSTREAM's own frames, before any translation or
 * rewrite, so three dialects reach it:
 *  - chat completions — `choices[].delta.content` / `.tool_calls` /
 *    `.reasoning` / `.reasoning_content`
 *  - Anthropic Messages — `content_block_delta` (`text_delta`,
 *    `input_json_delta`, `thinking_delta`) and a `tool_use` block start
 *  - OpenAI Responses — `response.output_text.delta`,
 *    `response.function_call_arguments.delta`, `response.reasoning_*.delta`
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

function nonEmptyArray(v) {
  return Array.isArray(v) && v.length > 0;
}

function chatKind(choices) {
  let reasoning = false;
  for (const choice of choices) {
    const delta = choice && typeof choice === 'object' ? choice.delta : undefined;
    if (!delta || typeof delta !== 'object') continue;
    if (nonEmptyString(delta.content) || nonEmptyArray(delta.tool_calls)) return 'content';
    if (nonEmptyString(delta.reasoning) || nonEmptyString(delta.reasoning_content)) reasoning = true;
  }
  return reasoning ? 'reasoning' : null;
}

function anthropicKind(frame) {
  if (frame.type === 'content_block_delta') {
    const d = frame.delta;
    if (!d || typeof d !== 'object') return null;
    if (d.type === 'text_delta' && nonEmptyString(d.text)) return 'content';
    if (d.type === 'input_json_delta' && nonEmptyString(d.partial_json)) return 'content';
    if (d.type === 'thinking_delta' && nonEmptyString(d.thinking)) return 'reasoning';
    return null;
  }
  // A tool call is announced by its block start, before any argument bytes.
  if (frame.type === 'content_block_start') {
    const b = frame.content_block;
    if (b && typeof b === 'object' && b.type === 'tool_use') return 'content';
  }
  return null;
}

const RESPONSES_CONTENT = new Set(['response.output_text.delta', 'response.function_call_arguments.delta']);
const RESPONSES_REASONING = new Set([
  'response.reasoning_text.delta',
  'response.reasoning_summary_text.delta',
  'response.reasoning.delta',
]);

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

  if (Array.isArray(frame.choices)) return chatKind(frame.choices);

  const type = frame.type;
  if (typeof type !== 'string') return null;
  if (type.startsWith('content_block_')) return anthropicKind(frame);
  if (RESPONSES_CONTENT.has(type)) return nonEmptyString(frame.delta) ? 'content' : null;
  if (RESPONSES_REASONING.has(type)) return nonEmptyString(frame.delta) ? 'reasoning' : null;
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
