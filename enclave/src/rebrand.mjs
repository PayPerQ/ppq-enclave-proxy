/**
 * Replace upstream brand mentions in the streamed response, mirroring
 * horse-power's utils/rebrandStream.ts (OPENROUTER -> PPQ.AI).
 *
 * PoC note: this does a per-chunk replace. A token split exactly across a chunk
 * boundary could be missed; the production port should carry a small tail buffer
 * (as rebrandStream.ts does). Cosmetic only — never affects billing or content
 * correctness.
 */

const NEEDLE = /openrouter/gi;
const REPLACEMENT = 'PPQ.AI';

export function rebrandChunk(chunk) {
  const s = chunk.toString('utf8');
  if (!/openrouter/i.test(s)) return chunk;
  return Buffer.from(s.replace(NEEDLE, REPLACEMENT), 'utf8');
}
