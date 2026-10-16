/**
 * Venice web-search citations on the direct path: translate them for the
 * client, and count the searches for the settle.
 *
 * WHY
 * ---
 * Every citation a PPQ client has ever rendered arrived as an OpenAI-style
 * annotation on a delta:
 *
 *     {"choices":[{"delta":{"annotations":[
 *        {"type":"url_citation","url_citation":{"url":"…","title":"…"}}]}}]}
 *
 * Venice sends something else. With `enable_web_search` on and
 * `include_search_results_in_stream` set (upstreams.mjs), the stream carries
 * one extra frame just before the usage frame:
 *
 *     {"choices":[],"venice_parameters":{…,"web_search_citations":[
 *        {"title":"…","url":"…","content":"…","date":"…"}]}}
 *
 * and only there — the message's own `annotations` is null (hp probe,
 * 2026-09-10). Left alone, the client would get a `choices: []` frame with a
 * vendor key no OpenAI client can read, and no sources.
 *
 * WHAT
 * ----
 * On a Venice-direct event stream that frame is REPLACED by an annotations
 * delta, so this route emits what the OpenRouter route does. A frame with no
 * citations (no search ran) is dropped. horse-power carries the same logic in
 * utils/veniceCitationStream.ts.
 *
 * BILLING
 * -------
 * Venice adds a flat per-search charge and bills only the searches it
 * performs. `searches` counts frames that RETURNED citations — evidence a
 * search ran, not the mode that was requested — and the enclave reports it on
 * the settle as `web_search_calls` for hp to price. It is counted from the
 * upstream's own bytes, before anything is rewritten.
 *
 * A non-streaming body is held and rewritten once at the end: the citations
 * move onto each choice's `message.annotations` (the same shape, on the whole
 * message) and the vendor key is removed. Seen live on the dev enclave
 * (2026-10-01): left alone, the body reached the client with
 * `venice_parameters` intact and no annotations at all.
 *
 * FAIL-OPEN
 * ---------
 * Only a line that parses as JSON AND carries `venice_parameters` is touched;
 * every other line passes through unchanged, as does any line longer than
 * MAX_LINE_CHARS. A non-streaming body that does not parse, or is larger
 * than MAX_JSON_BODY_BYTES, is released as it came.
 *
 * CONTENT-FREE
 * ------------
 * Text is parsed only to be re-emitted to the same client. Nothing is
 * retained past feed()/finish(), logged, or exported; `searches` is a count.
 */
import { StringDecoder } from 'node:string_decoder';

/** Longest SSE line parsed; a longer one passes through raw. */
export const MAX_LINE_CHARS = 1_000_000;
/** Largest non-streaming body rewritten, in bytes; a larger one passes through raw. */
export const MAX_JSON_BODY_BYTES = 16_000_000;

/**
 * The `web_search_citations` array on one SSE line, or null when the line
 * carries none. An EMPTY array, distinct from null, is a Venice frame that ran
 * no search.
 */
export function parseVeniceCitations(line) {
  // Cheap reject first: this runs on every line of every Venice stream.
  if (!line.includes('venice_parameters')) return null;
  const payload = line.startsWith('data:') ? line.slice(5).trim() : line.trim();
  if (payload === '[DONE]' || payload === '') return null;
  try {
    const parsed = JSON.parse(payload);
    const vp = parsed?.venice_parameters;
    if (!vp || typeof vp !== 'object') return null;
    const cites = vp.web_search_citations;
    if (!Array.isArray(cites)) return [];
    return cites.filter((c) => c && typeof c === 'object');
  } catch {
    // A line that merely contains the word — model output, a split frame — is
    // not a Venice frame. No evidence is no search, and the line is left alone.
    return null;
  }
}

/** 1 when the frame shows a search actually ran (citations returned), else 0. */
export function countVeniceSearches(citations) {
  return citations && citations.length > 0 ? 1 : 0;
}

function toAnnotations(citations) {
  const out = [];
  for (const c of citations) {
    // A citation with no URL is unrenderable; dropping it keeps the numbering
    // dense over links that work.
    if (typeof c.url !== 'string' || c.url === '') continue;
    out.push({
      type: 'url_citation',
      url_citation: {
        url: c.url,
        ...(typeof c.title === 'string' && c.title ? { title: c.title } : {}),
        ...(typeof c.content === 'string' && c.content ? { content: c.content } : {}),
      },
    });
  }
  return out;
}

/** One SSE line translated: the line to emit, or null to drop it. */
export function translateVeniceLine(line) {
  const citations = parseVeniceCitations(line);
  if (citations === null) return line;
  if (citations.length === 0) return null;
  const payload = line.startsWith('data:') ? line.slice(5).trim() : line.trim();
  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return line;
  }
  const annotations = toAnnotations(citations);
  if (annotations.length === 0) return null;
  return `data: ${JSON.stringify({
    id: parsed.id,
    object: parsed.object ?? 'chat.completion.chunk',
    created: parsed.created,
    model: parsed.model,
    choices: [{ index: 0, delta: { annotations }, logprobs: null, finish_reason: null }],
  })}`;
}

/**
 * A whole (non-streaming) body translated. Returns the body to send and the
 * searches it evidences; the input unchanged when it is not a Venice body.
 */
export function translateVeniceBody(body) {
  if (!body.includes('venice_parameters')) return { body, searches: 0 };
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { body, searches: 0 };
  }
  const vp = parsed?.venice_parameters;
  if (!vp || typeof vp !== 'object' || Array.isArray(vp)) return { body, searches: 0 };
  const cites = Array.isArray(vp.web_search_citations)
    ? vp.web_search_citations.filter((c) => c && typeof c === 'object')
    : [];
  const annotations = toAnnotations(cites);
  if (annotations.length > 0 && Array.isArray(parsed.choices)) {
    for (const choice of parsed.choices) {
      const message = choice?.message;
      if (!message || typeof message !== 'object') continue;
      // Never overwrite annotations the upstream set itself.
      if (!Array.isArray(message.annotations) || message.annotations.length === 0) {
        message.annotations = annotations;
      }
    }
  }
  delete parsed.venice_parameters;
  return { body: JSON.stringify(parsed), searches: countVeniceSearches(cites) };
}

export class VeniceCitationTranslator {
  /** @param {{sse: boolean}} opts whether the response is an event stream */
  constructor({ sse }) {
    this.sse = sse === true;
    this.decoder = new StringDecoder('utf8');
    this.carry = '';
    /** Searches the upstream gave evidence of. Reported on the settle. */
    this.searches = 0;
    // Non-streaming: the body held for one rewrite in finish().
    this.held = [];
    this.heldBytes = 0;
    this.passthrough = false;
  }

  #line(line) {
    if (line.trim() === '' || line.length > MAX_LINE_CHARS) return line;
    this.searches += countVeniceSearches(parseVeniceCitations(line));
    return translateVeniceLine(line);
  }

  /** @param {Buffer} chunk @returns {Buffer} what to send on for this chunk */
  feed(chunk) {
    if (!this.sse) {
      if (this.passthrough) return chunk;
      this.held.push(chunk);
      this.heldBytes += chunk.length;
      if (this.heldBytes > MAX_JSON_BODY_BYTES) {
        // Too big to rewrite: release what is held and stop buffering.
        const out = Buffer.concat(this.held);
        this.held = [];
        this.passthrough = true;
        return out;
      }
      return Buffer.alloc(0);
    }
    this.carry += this.decoder.write(chunk);
    const lastNewline = this.carry.lastIndexOf('\n');
    if (lastNewline === -1) {
      // No complete line yet. A line this long is not a citation frame worth
      // holding the stream for: release it raw.
      if (this.carry.length <= MAX_LINE_CHARS) return Buffer.alloc(0);
      const raw = this.carry;
      this.carry = '';
      return Buffer.from(raw, 'utf8');
    }
    const complete = this.carry.slice(0, lastNewline);
    this.carry = this.carry.slice(lastNewline + 1);
    const kept = [];
    let dropped = false;
    for (const line of complete.split('\n')) {
      // The blank line that terminated a dropped frame goes with it, so no
      // empty event is left behind.
      if (dropped && line.trim() === '') {
        dropped = false;
        continue;
      }
      dropped = false;
      const out = this.#line(line);
      if (out === null) {
        dropped = true;
        continue;
      }
      kept.push(out);
    }
    return kept.length === 0 ? Buffer.alloc(0) : Buffer.from(kept.join('\n') + '\n', 'utf8');
  }

  /** @returns {Buffer} what is still owed: the held body, or a final partial line */
  finish() {
    if (!this.sse) {
      if (this.passthrough || this.held.length === 0) return Buffer.alloc(0);
      const raw = Buffer.concat(this.held);
      this.held = [];
      const { body, searches } = translateVeniceBody(raw.toString('utf8'));
      this.searches += searches;
      // Untouched bodies go out as the bytes that came in.
      return searches === 0 && !raw.includes('venice_parameters') ? raw : Buffer.from(body, 'utf8');
    }
    this.carry += this.decoder.end();
    if (this.carry.length === 0) return Buffer.alloc(0);
    const out = this.#line(this.carry);
    this.carry = '';
    return out === null ? Buffer.alloc(0) : Buffer.from(out, 'utf8');
  }
}
