/**
 * Streaming string replacement over a chunked response, with two correctness
 * properties a naive per-chunk replace lacks:
 *   1. Carry buffer: a needle split across a chunk boundary ("OPEN" | "ROUTER",
 *      or a model id split mid-slug) is still rewritten — the trailing partial
 *      match is held back until the next chunk. A streaming TextDecoder handles
 *      multi-byte UTF-8 splits too.
 *   2. Case-sensitive, literal tokens: a model answer that mentions a needle in
 *      passing is only rewritten on an exact match.
 *
 * Used for two things on the response stream:
 *   - OpenRouter branding: `OPENROUTER` → `PPQ.AI` (the `Rebrander` subclass).
 *   - Direct-provider model id: `accounts/fireworks/models/…` → the public
 *     `or_slug`, so a direct upstream is invisible to the client.
 */
export class StreamReplacer {
  /** @param pairs Array<[needle, replacement]>, applied in order. */
  constructor(pairs) {
    this.pairs = (pairs || []).filter(([n]) => typeof n === 'string' && n.length > 0);
    this.maxNeedle = this.pairs.reduce((m, [n]) => Math.max(m, n.length), 1);
    this.carry = '';
    this.decoder = new TextDecoder();
  }

  /** Feed a response chunk; returns the (rewritten) bytes safe to forward now. */
  feed(chunk) {
    let s = this.carry + this.decoder.decode(chunk, { stream: true });
    this.carry = '';
    for (const [needle, replacement] of this.pairs) {
      s = s.split(needle).join(replacement);
    }
    // Hold back the longest trailing run that could be the START of any needle,
    // so a token straddling this boundary is completed + matched next feed.
    const maxK = Math.min(this.maxNeedle - 1, s.length);
    for (let k = maxK; k > 0; k--) {
      const tail = s.slice(s.length - k);
      if (this.pairs.some(([n]) => n.length > k && n.slice(0, k) === tail)) {
        this.carry = tail;
        s = s.slice(0, s.length - k);
        break;
      }
    }
    return Buffer.from(s, 'utf8');
  }

  /** Flush any held-back tail at end of stream. */
  finish() {
    const out = Buffer.from(this.carry, 'utf8');
    this.carry = '';
    return out;
  }
}

/** OpenRouter heartbeat/branding rebrand: `OPENROUTER` → `PPQ.AI`. */
export class Rebrander extends StreamReplacer {
  constructor() {
    super([['OPENROUTER', 'PPQ.AI']]);
  }
}

/**
 * Response rewriter for a DIRECT upstream: hide the wire model id behind the
 * public slug (+ the OpenRouter rebrand, harmless if the token never appears).
 */
export function directResponseRewriter(upstreamModelId, orSlug) {
  const pairs = [];
  if (upstreamModelId && orSlug && upstreamModelId !== orSlug) {
    pairs.push([upstreamModelId, orSlug]);
  }
  pairs.push(['OPENROUTER', 'PPQ.AI']);
  return new StreamReplacer(pairs);
}

/**
 * A model-KEY rewriter for a direct answer whose wire id may come back with a
 * tail the literal StreamReplacer cannot know in advance: OpenAI's Responses
 * API echoes the dated snapshot (`"model":"gpt-5.5-2026-04-23"`) for a bare
 * `gpt-5.5` request (horse-power #1156). Rewrites exactly the JSON member
 * `"model":"<upstream>"` or `"model":"<upstream>-YYYY-MM-DD"` to
 * `"model":"<orSlug>"`, nothing else: the id inside model OUTPUT cannot match
 * because quotes inside a JSON string value are escaped, so the unescaped
 * `"model":"` sequence never occurs within content. The same discipline as
 * horse-power utils/modelRewriteStream.ts.
 *
 * Chunk boundaries: complete lines (SSE `data:` frames) are rewritten and
 * emitted as they arrive; the trailing partial line is carried. A
 * non-streaming JSON body has no newlines, so once the carry passes
 * FORCE_FLUSH_BYTES the rewritten head is emitted and a TAIL_KEEP tail (longer
 * than any possible match) is kept, so a member split across the cut still
 * rewrites. feed()/finish() return Buffers, the StreamReplacer contract.
 */
const MODEL_KEY_TAIL_KEEP = 512;
const MODEL_KEY_FORCE_FLUSH_BYTES = 8192;
const DATED_SNAPSHOT = '(?:-\\d{4}-\\d{2}-\\d{2})?';
export class ModelKeyRewriter {
  constructor(upstreamModelId, orSlug) {
    const escaped = String(upstreamModelId ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    this.enabled = Boolean(upstreamModelId && orSlug && upstreamModelId !== orSlug);
    this.pattern = new RegExp(`"model"\\s*:\\s*"${escaped}${DATED_SNAPSHOT}"`, 'g');
    this.replacement = `"model":${JSON.stringify(String(orSlug ?? ''))}`;
    this.carry = '';
    this.decoder = new TextDecoder();
  }
  rewrite(text) {
    return this.enabled ? text.replace(this.pattern, this.replacement) : text;
  }
  feed(chunk) {
    this.carry += this.decoder.decode(chunk, { stream: true });
    let out = '';
    const lastNewline = this.carry.lastIndexOf('\n');
    if (lastNewline !== -1) {
      out += this.rewrite(this.carry.slice(0, lastNewline + 1));
      this.carry = this.carry.slice(lastNewline + 1);
    }
    if (this.carry.length > MODEL_KEY_FORCE_FLUSH_BYTES) {
      // Rewrite FIRST, then split: cutting before rewriting could sever a
      // match across the cut, leaving both halves raw.
      const rewritten = this.rewrite(this.carry);
      let cut = rewritten.length - MODEL_KEY_TAIL_KEEP;
      // Never cut between the two halves of a surrogate pair: an astral
      // character (an emoji in the echoed instructions) straddling the cut
      // would reach the client as two U+FFFD (CodeRabbit on #386).
      const prev = rewritten.charCodeAt(cut - 1);
      if (prev >= 0xd800 && prev <= 0xdbff) cut -= 1;
      out += rewritten.slice(0, cut);
      this.carry = rewritten.slice(cut);
    }
    return Buffer.from(out, 'utf8');
  }
  finish() {
    const out = this.rewrite(this.carry + this.decoder.decode());
    this.carry = '';
    return Buffer.from(out, 'utf8');
  }
}
