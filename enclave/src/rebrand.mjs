/**
 * Rebrand the upstream heartbeat/branding token in the streamed response
 * (OpenRouter emits `: OPENROUTER PROCESSING` comment lines), mirroring the
 * intent of horse-power's utils/rebrandStream.ts.
 *
 * Two correctness properties the naive per-chunk replace lacked:
 *   1. Carry buffer: a token split across a chunk boundary ("OPEN" | "ROUTER")
 *      is still rewritten — we hold back a trailing partial match until the next
 *      chunk. A streaming TextDecoder handles multi-byte UTF-8 splits too.
 *   2. Case-sensitive, all-caps only: we replace the literal `OPENROUTER` token,
 *      NOT a case-insensitive match — so a model answer that mentions
 *      "OpenRouter" (mixed case) is passed through untouched instead of being
 *      silently corrupted.
 */

const NEEDLE = 'OPENROUTER';
const REPLACEMENT = 'PPQ.AI';

export class Rebrander {
  constructor() {
    this.carry = '';
    this.decoder = new TextDecoder();
  }

  /** Feed a response chunk; returns the (rebranded) bytes safe to forward now. */
  feed(chunk) {
    let s = this.carry + this.decoder.decode(chunk, { stream: true });
    this.carry = '';
    s = s.split(NEEDLE).join(REPLACEMENT);
    // Hold back the longest trailing run that could be the start of NEEDLE, so a
    // token straddling this chunk boundary is completed (and matched) next feed.
    const maxK = Math.min(NEEDLE.length - 1, s.length);
    for (let k = maxK; k > 0; k--) {
      if (s.slice(s.length - k) === NEEDLE.slice(0, k)) {
        this.carry = s.slice(s.length - k);
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
