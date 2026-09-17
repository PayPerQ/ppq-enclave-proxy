/**
 * Input-size measurement for horse-power's pre-flight balance check (#171).
 *
 * hp bounds a request's INPUT cost at /enclave/authorize, before the upstream
 * is paid. It used to receive only the serialized length of `messages`, which
 * it divided by two. That bound failed in both directions (measured
 * 2026-09-17 against real `prompt_tokens` on 8 models):
 *   - base64 images/files counted as text, so one attachment read as millions
 *     of tokens and affordable private-mode requests were refused (402 → the
 *     browser silently fell back to the NON-private path);
 *   - it still UNDER-counted Claude's tokenizer on symbol-dense text (0.37×).
 *
 * So the enclave counts text with a real tokenizer and reports media parts
 * separately, by size. It deliberately knows nothing about model families:
 * o200k is exact for OpenAI and within a few percent for DeepSeek/Kimi/Grok on
 * ordinary text, and hp owns the per-family correction (Claude, Gemini, …)
 * along with the catalog. New models and retuned factors need no rotation.
 *
 * Everything returned is a count: no content leaves the enclave.
 */

/** Text beyond this is not tokenized (bigger than any context window). hp
 *  then falls back to the byte bound. Bounds the CPU spent per request. */
export const MAX_TOKENIZE_CHARS = 2_000_000;

/**
 * BPE cost is QUADRATIC in the length of a run without whitespace: measured, an
 * 8k-char run of one letter takes 29 ms, 16k 113 ms, 64k seconds. Any user
 * controls that input, so text is counted in slices this short (a 2k run costs
 * ~2.5 ms). Cuts shift a count by at most two tokens each, upward (+0.2–0.4% on prose),
 * which is noise next to hp's family factors.
 */
export const TOKENIZE_SLICE_CHARS = 2_000;

/**
 * Counting runs BEFORE hp has authenticated the caller (it is an input to that
 * call), so a forged credit id can make a worker tokenize up to
 * MAX_TOKENIZE_CHARS. Yielding every this-many chars keeps other streams on the
 * worker flowing meanwhile.
 */
export const YIELD_EVERY_CHARS = 64_000;

const yieldToEventLoop = () => new Promise((resolve) => setImmediate(resolve));

let tokenizerPromise = null;

/**
 * Loads the o200k encoder once per process. ~120 ms and ~90 MB, so serving
 * processes call this at startup instead of paying it on a user's request.
 * Resolves to null if the module cannot load: counting is an optimisation of
 * a spend check, never a reason to fail a request.
 */
export function loadTokenizer() {
  tokenizerPromise ??= import('gpt-tokenizer/encoding/o200k_base').then(
    (m) => m.countTokens,
    () => null,
  );
  return tokenizerPromise;
}

/** Decoded byte size of a base64 string or `data:` URL (padding ignored). */
export function base64DecodedBytes(value) {
  if (typeof value !== 'string') return 0;
  const comma = value.startsWith('data:') ? value.indexOf(',') : -1;
  const b64 = comma >= 0 ? value.slice(comma + 1) : value;
  let len = b64.length;
  while (len > 0 && (b64[len - 1] === '=' || b64[len - 1] === '\n' || b64[len - 1] === '\r')) len--;
  return Math.floor((len * 3) / 4);
}

/**
 * A copy of one content part with its media payload removed, tallied into
 * `media`. Unknown part types are returned untouched, so they are counted as
 * text: an over-count is the safe direction for a spend check.
 */
function stripMediaPart(part, media) {
  if (!part || typeof part !== 'object') return part;
  switch (part.type) {
    case 'image_url':
      media.image_parts++;
      return { type: part.type };
    case 'image': // Anthropic-shaped part, occasionally sent to chat completions
      media.image_parts++;
      return { type: part.type };
    case 'input_audio':
      media.audio_bytes += base64DecodedBytes(part.input_audio?.data);
      return { type: part.type };
    case 'file':
      media.file_bytes += base64DecodedBytes(part.file?.file_data);
      return { type: part.type, filename: part.file?.filename };
    default:
      return part;
  }
}

/**
 * Measures a chat-completions payload for hp's authorize bound.
 *
 * Returns `{ message_count, image_parts, file_bytes, audio_bytes,
 * input_tokens_o200k }`. `input_tokens_o200k` is absent when the text is too
 * large or the tokenizer is unavailable, which tells hp to use `input_bytes`.
 * Never throws.
 *
 * The count covers each message serialized as JSON with media blanked — not
 * just its text — so tool calls, tool results, names, reasoning blocks and any
 * field added later are all included. JSON punctuation over-counts a few
 * tokens per message; hp adds its own per-message overhead on top.
 */
export async function measureInput(payload) {
  const media = { image_parts: 0, file_bytes: 0, audio_bytes: 0 };
  const messages = Array.isArray(payload?.messages) ? payload.messages : [];
  const out = { message_count: messages.length, ...media };
  try {
    const texts = [];
    for (const m of messages) {
      if (m && typeof m === 'object' && Array.isArray(m.content)) {
        texts.push(JSON.stringify({ ...m, content: m.content.map((p) => stripMediaPart(p, media)) }));
      } else {
        texts.push(JSON.stringify(m ?? null));
      }
    }
    // Tool definitions are billed input too, and were never in the old bound.
    if (Array.isArray(payload?.tools) && payload.tools.length) texts.push(JSON.stringify(payload.tools));
    Object.assign(out, media);

    const totalChars = texts.reduce((n, t) => n + t.length, 0) + texts.length;
    if (totalChars > MAX_TOKENIZE_CHARS) return out;
    const countTokens = await loadTokenizer();
    if (!countTokens) return out;
    // User text may contain special-token strings like "<|endoftext|>". The
    // library throws on them by default, which would let any user push their own
    // request off the precise bound; count them as ordinary text instead.
    const opts = { disallowedSpecial: new Set() };
    let tokens = 0;
    let sinceYield = 0;
    for (const t of texts) {
      for (let i = 0; i < t.length || i === 0; i += TOKENIZE_SLICE_CHARS) {
        const slice = t.slice(i, i + TOKENIZE_SLICE_CHARS);
        if (sinceYield + slice.length > YIELD_EVERY_CHARS) {
          await yieldToEventLoop();
          sinceYield = 0;
        }
        tokens += countTokens(slice, opts);
        sinceYield += slice.length;
      }
    }
    // One separator token per message boundary, as the joined text counted.
    out.input_tokens_o200k = tokens + Math.max(0, texts.length - 1);
  } catch {
    // Malformed payload shapes: return what was tallied; hp falls back.
  }
  return out;
}
