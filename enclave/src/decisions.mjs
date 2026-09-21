/**
 * `/v1/decisions` — OpenRouter's structured-decision modality (TypeSafe's Jev
 * "System One" models), served IN the enclave so the state being judged is as
 * private as a chat prompt.
 *
 * These models are not chat models: OpenRouter refuses them on
 * `/api/v1/chat/completions` ("is a decisions model … use /api/alpha/decisions")
 * and they never appear in the default model list. The request is
 * `{ model, state, questions }` and the answer is ONE JSON body — no SSE, no
 * messages, no tools, no provider routing block — so nothing in routing.mjs,
 * eligibility.mjs or the direct-provider candidates applies. This module holds
 * the parts that are pure: the validator, the input measure hp bounds spend
 * with, and the usage extraction the settle is built from. server.mjs owns the
 * handler (it needs the tunnels, EHBP and the settle queue).
 *
 * MIRRORED in horse-power (`services/decisionsPayload.ts`), which serves the
 * same route on the enclave-bypass host. hp's
 * `services/enclaveDecisionsConformance.test.ts` runs one fixture set through
 * both validators and asserts deep equality — every field name and message
 * below is part of that contract. Contract source: OpenRouter's own validator,
 * pinned by live probes 2026-09-21 (stricter than the `@typesafe-ai/sdk` types
 * in two places: `state` and every `instructions` are required and non-null;
 * `noul` criteria is an object; `choice` descriptions may be null, `score`
 * entries may not; extra question properties are forwarded).
 */
import { TOKENIZE_SLICE_CHARS, YIELD_EVERY_CHARS, loadTokenizer } from './inputEstimate.mjs';

/** The path on openrouter.ai. The v1 chat path is a literal in server.mjs for the same reason. */
export const DECISIONS_UPSTREAM_PATH = '/api/alpha/decisions';
/** The `endpoint` value sent on authorize and settle so hp takes its decisions branch. */
export const DECISIONS_ENDPOINT = 'decisions';
/** hp's cost_source label for this path (registered in its costConfidence map). */
export const DECISIONS_COST_SOURCE = 'decisions-usage';

export const DECISION_QUESTION_TYPES = Object.freeze(['noul', 'choice', 'score']);
export const MAX_QUESTIONS = 50;
export const MAX_CRITERIA = 100;
export const MAX_STATE_CHARS = 100_000;
/**
 * Bound on the whole serialized `{ state, questions }` (instructions, criteria
 * descriptions and forwarded extras have no per-field cap). It is also what
 * keeps the PRE-AUTHORIZE tokenizer below honest: BPE cost grows with input,
 * and this runs before hp has vouched for the caller.
 */
export const MAX_REQUEST_CHARS = 150_000;
/** The upstream's JSON answer is small; a 1 MB cap keeps a misbehaving upstream out of memory. */
export const MAX_RESPONSE_BYTES = 1024 * 1024;
/**
 * Wire-body cap, read BEFORE authorize: MAX_REQUEST_CHARS of JSON plus EHBP
 * framing and AEAD overhead fits in a fraction of this; the chat path's 25 MB
 * default exists for attachments a decisions body never carries.
 */
export const MAX_REQUEST_BODY_BYTES = 1024 * 1024;

const isPlainRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isEntry = (v) => typeof v === 'string' || Array.isArray(v) || isPlainRecord(v);
const isDescription = (v) => v === null || isEntry(v);

/**
 * Validate a decisions body. Returns `{ kind: 'ok', value }` with only the
 * three defined top-level fields (unknown keys are dropped — upstream ignores
 * them, so forwarding verbatim would let a caller smuggle undocumented
 * parameters), or `{ kind: 'invalid', error: { field, message } }`.
 */
export function validateDecisionsRequest(body) {
  const fail = (field, message) => ({ kind: 'invalid', error: { field, message } });

  if (!isPlainRecord(body)) return fail('body', 'Request body must be a JSON object');

  const { model, state, questions } = body;

  if (typeof model !== 'string' || model.trim() === '') {
    return fail('model', 'Missing required field: model');
  }

  if (state === undefined) return fail('state', 'Missing required field: state');
  if (!isEntry(state)) return fail('state', 'state must be a string, object, or array');
  if (typeof state === 'string') {
    if (state.length > MAX_STATE_CHARS) {
      return fail('state', `state must be at most ${MAX_STATE_CHARS} characters`);
    }
  } else if (JSON.stringify(state).length > MAX_STATE_CHARS) {
    return fail('state', `state must serialize to at most ${MAX_STATE_CHARS} characters`);
  }

  if (!isPlainRecord(questions)) {
    return fail('questions', 'Missing required field: questions (an object of question definitions)');
  }

  const keys = Object.keys(questions);
  if (keys.length === 0) return fail('questions', 'At least one question is required');
  if (keys.length > MAX_QUESTIONS) {
    return fail('questions', `At most ${MAX_QUESTIONS} questions are allowed`);
  }

  for (const key of keys) {
    const q = questions[key];
    const at = `questions.${key}`;
    if (!isPlainRecord(q)) return fail(at, 'Each question must be an object');

    const type = q.type;
    if (typeof type !== 'string' || !DECISION_QUESTION_TYPES.includes(type)) {
      return fail(`${at}.type`, `type must be one of: ${DECISION_QUESTION_TYPES.join(', ')}`);
    }

    if (q.instructions === undefined) {
      return fail(`${at}.instructions`, 'Missing required field: instructions');
    }
    if (!isEntry(q.instructions)) {
      return fail(`${at}.instructions`, 'instructions must be a string, object, or array');
    }

    if (type === 'choice') {
      if (!isPlainRecord(q.criteria)) {
        return fail(`${at}.criteria`, 'choice questions require criteria as an object of option -> description');
      }
      const options = Object.keys(q.criteria);
      if (options.length === 0) {
        return fail(`${at}.criteria`, 'choice questions require at least 1 option');
      }
      if (options.length > MAX_CRITERIA) {
        return fail(`${at}.criteria`, `at most ${MAX_CRITERIA} options are allowed`);
      }
      for (const opt of options) {
        if (!isDescription(q.criteria[opt])) {
          return fail(`${at}.criteria.${opt}`, 'each option description must be a string, object, array, or null');
        }
      }
    } else if (type === 'score') {
      if (!Array.isArray(q.criteria)) {
        return fail(`${at}.criteria`, 'score questions require criteria as an array of ordered labels');
      }
      if (q.criteria.length === 0) {
        return fail(`${at}.criteria`, 'score questions require at least 1 label');
      }
      if (q.criteria.length > MAX_CRITERIA) {
        return fail(`${at}.criteria`, `at most ${MAX_CRITERIA} labels are allowed`);
      }
      if (q.criteria.some((c) => !isEntry(c))) {
        return fail(`${at}.criteria`, 'each label must be a string, object, or array');
      }
    } else if (q.criteria !== undefined && !isPlainRecord(q.criteria)) {
      return fail(`${at}.criteria`, 'noul criteria must be an object describing the true/false outcomes');
    }
  }

  if (JSON.stringify({ state, questions }).length > MAX_REQUEST_CHARS) {
    return fail('questions', `state and questions together must serialize to at most ${MAX_REQUEST_CHARS} characters`);
  }

  return { kind: 'ok', value: { model, state, questions } };
}

const yieldToEventLoop = () => new Promise((resolve) => setImmediate(resolve));

/**
 * What hp's authorize bounds spend with: the o200k count of the serialized
 * `{ state, questions }` plus its byte size (the fallback when the count is
 * unavailable). Counts only — never the content. hp applies the model factor
 * and the fixed preamble the upstream charges (decisionsPayload.ts), so a
 * retuned factor never needs a rotation. Never throws.
 *
 * Runs BEFORE authorize, on input only the validator has vetted, so it is
 * bounded the way measureInput is: the validator's MAX_REQUEST_CHARS caps the
 * text, it is tokenized in slices, and the loop yields so one request cannot
 * monopolise the worker.
 */
export async function measureDecisionsInput(request) {
  const serialized = JSON.stringify({ state: request.state, questions: request.questions });
  const out = {
    endpoint: DECISIONS_ENDPOINT,
    input_bytes: Buffer.byteLength(serialized),
    message_count: 0,
    image_parts: 0,
    file_bytes: 0,
    audio_bytes: 0,
  };
  try {
    if (serialized.length > MAX_REQUEST_CHARS) return out;
    const countTokens = await loadTokenizer();
    if (!countTokens) return out;
    // Special-token strings in user text count as ordinary text (see measureInput).
    const opts = { disallowedSpecial: new Set() };
    let tokens = 0;
    let sinceYield = 0;
    for (let i = 0; i < serialized.length || i === 0; i += TOKENIZE_SLICE_CHARS) {
      const slice = serialized.slice(i, i + TOKENIZE_SLICE_CHARS);
      if (sinceYield + slice.length > YIELD_EVERY_CHARS) {
        await yieldToEventLoop();
        sinceYield = 0;
      }
      tokens += countTokens(slice, opts);
      sinceYield += slice.length;
    }
    out.input_tokens_o200k = tokens;
  } catch {
    // hp falls back to input_bytes.
  }
  return out;
}

/**
 * Billing facts from the upstream's JSON answer: `usage.cost` is OpenRouter's
 * inline invoice for the call (it reconciles exactly with input_tokens x the
 * rate card; completion tokens are priced at $0), `id` is a `gen-dec-…`
 * generation id hp can re-fetch on a zero cost. A body without usage yields
 * zeros — hp's settle then records a $0 row with this cost_source, which is
 * visible, rather than nothing.
 */
export function decisionsUsage(body) {
  const usage = body && typeof body === 'object' ? body.usage : undefined;
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);
  return {
    inputTokens: num(usage?.input_tokens),
    outputTokens: num(usage?.output_tokens),
    totalCost: num(usage?.cost),
    generationId: typeof body?.id === 'string' && body.id.startsWith('gen-') ? body.id : '',
    servedModel: typeof body?.model === 'string' ? body.model : undefined,
  };
}
