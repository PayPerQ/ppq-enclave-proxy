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
