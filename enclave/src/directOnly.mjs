/**
 * Models that exactly one upstream can serve — and what to answer when the
 * enclave cannot serve them.
 *
 * Every direct candidate is an optimisation with OpenRouter behind it: when
 * one is skipped or fails, the loop in server.mjs moves on and OpenRouter
 * answers by the slower road. That encodes "anything we cannot serve direct,
 * OpenRouter can serve", and Venice is the provider for which it is false.
 * No `venice/*` id has an OpenRouter twin, so the fallback posts an id
 * OpenRouter has never heard of and the user reads back
 *
 *     venice/venice-uncensored-1-2 is not a valid model ID
 *
 * — a sentence that says the model does not exist, about a model that does,
 * for a request that failed for an unrelated reason (too many images, an
 * unsupported image type, `logit_bias`, a missing key).
 *
 * This module answers instead. It is a port of horse-power's
 * services/directProviders/directOnly.ts, narrowed to what the enclave can
 * know: a skip reason from the candidate builder, or the status of an attempt
 * that failed. The messages are hp's, so the two routes say the same thing.
 *
 * No upstream provider is ever named in a string the caller sees. They asked
 * for a PPQ model id; the answer talks about that id and what to do next.
 *
 * Pure: no I/O, no clock. Nothing here is logged or retained; the only
 * request-derived values in a message are the model id and a field NAME,
 * both returned to the caller who sent them.
 */

/**
 * Namespaces with no OpenRouter twin. The enclave holds no catalog, so this is
 * stated rather than derived — the same list, for the same reason, as the
 * family binding in upstreamBinding.mjs. Keep in sync with hp
 * directOnly.ts DIRECT_ONLY_SEEDS.
 */
export const DIRECT_ONLY_NAMESPACES = Object.freeze([
  { prefix: 'venice/', provider: 'venice' },
  // Fireworks' FireRouter (horse-power #1034): `firerouter/auto|eco|premium`
  // are PPQ ids for a route only Fireworks' endpoint resolves. OpenRouter has
  // never heard of them, so a skipped or failed candidate is answered here.
  { prefix: 'firerouter/', provider: 'firerouter' },
]);

/** The namespace `model` belongs to, or undefined when it is not direct-only. */
export function directOnlyNamespaceFor(model) {
  if (typeof model !== 'string' || model.length === 0) return undefined;
  return DIRECT_ONLY_NAMESPACES.find((ns) => model.startsWith(ns.prefix));
}

/** True when falling back to OpenRouter for this model would produce a lie. */
export function isDirectOnlyModel(model) {
  return directOnlyNamespaceFor(model) !== undefined;
}

export const DIRECT_ONLY_UNSUPPORTED_CODE = 'direct_only_model_unsupported_request';
export const DIRECT_ONLY_UNAVAILABLE_CODE = 'direct_only_model_unavailable';
export const DIRECT_ONLY_RATE_LIMITED_CODE = 'direct_only_model_rate_limited';
export const DIRECT_ONLY_UPSTREAM_CODE = 'direct_only_model_upstream_error';
export const DIRECT_ONLY_NOT_FOUND_CODE = 'model_not_found';

const unavailable = (model) => ({
  status: 503,
  type: 'api_error',
  code: DIRECT_ONLY_UNAVAILABLE_CODE,
  message: `The model "${model}" is temporarily unavailable. Please try again shortly.`,
});
const notFound = (model) => ({
  status: 404,
  type: 'invalid_request_error',
  code: DIRECT_ONLY_NOT_FOUND_CODE,
  message: `The model "${model}" does not exist or is not available to your account.`,
});
const rateLimited = (model) => ({
  status: 429,
  type: 'rate_limit_error',
  code: DIRECT_ONLY_RATE_LIMITED_CODE,
  message: `The model "${model}" is rate limited right now. Please retry in a few seconds.`,
});
const upstreamError = (model) => ({
  status: 502,
  type: 'api_error',
  code: DIRECT_ONLY_UPSTREAM_CODE,
  message: `The model "${model}" could not be served because of an upstream error. Please try again; if it persists, contact support.`,
});
const unsupported = (message) => ({
  status: 400,
  type: 'invalid_request_error',
  code: DIRECT_ONLY_UNSUPPORTED_CODE,
  message,
});

/**
 * Skip reasons that mean "real model, not reachable from here right now":
 * no tunnel or key provisioned, a family/host pairing the binding refused,
 * a row hp disabled. A retry may succeed; nothing about the request is wrong.
 */
const UNAVAILABLE_REASONS = new Set(['no_tunnel_or_key', 'upstream_not_bound_to_family', 'model_disabled']);

/**
 * Skip reasons that mean the caller asked for something this model cannot do,
 * with the sentence that says so. `ctx` carries what the candidate states
 * about the row. Mirror of hp directOnly.ts REASON_TABLE.
 */
const UNSUPPORTED_MESSAGES = {
  web_search_requires_openrouter: (m) =>
    `The model "${m}" does not support web search. Retry without the web search plugin or tool, or choose a model that supports it.`,
  zdr_requested: (m) =>
    `The model "${m}" does not support zero data retention. Retry without "provider.zdr", or choose a model that supports it.`,
  or_routing_suffix: (m) =>
    `The model "${m}" does not support routing suffixes. Request the model id without the ":" suffix.`,
  unsupported_field: (m, field) =>
    field
      ? `The request field "${field}" is not supported by the model "${m}". Remove it and retry.`
      : `The request contains a field the model "${m}" does not support. Remove it and retry.`,
  unsupported_message_field: (m) =>
    `A message in this request carries a field the model "${m}" does not support. Remove it and retry.`,
  // Two answers, because "remove the image" is wrong advice on a row that
  // takes images: there the skip means a format or transport this route
  // cannot carry (heic, gif, a remote URL, a file part, an oversized image).
  non_text_content: (m, _field, ctx) =>
    ctx.supportsImages
      ? `The model "${m}" accepts text and PNG, JPEG or WebP images sent as base64 data URLs. Remove other attachments, remote image URLs or oversized images and retry.`
      : `The model "${m}" accepts text-only messages. Remove image or file content from the conversation and retry.`,
  // The limit is the one the request was actually held to (upstreams.mjs puts
  // it in the skip), so the sentence cannot disagree with the refusal.
  too_many_images: (m, field) => {
    const max = Number.parseInt(field, 10);
    return Number.isInteger(max) && max >= 0
      ? `The model "${m}" accepts at most ${max} image${max === 1 ? '' : 's'} per message. Send fewer images in one message and retry.`
      : `The model "${m}" accepts fewer images per message than this request sent. Send fewer images in one message and retry.`;
  },
  tools_unsupported_by_model: (m) =>
    `The model "${m}" does not support tool calling. Retry without "tools", or choose a model that supports it.`,
  response_format_unsupported: (m) =>
    `The model "${m}" does not support the requested "response_format". Retry without it, or choose a model that supports it.`,
  malformed_messages: (m) =>
    `The "messages" array is not valid for the model "${m}". Each message needs a role and text content.`,
  endpoint_not_chat_completions: (m) => `The model "${m}" is only available on the chat completions endpoint.`,
  unmappable_field: (m, field) =>
    field
      ? `The request field "${field}" is not supported by the model "${m}". Remove it and retry.`
      : `The request contains an option the model "${m}" cannot be served with. Remove it and retry.`,
};

/**
 * A field name is caller text. It is echoed only when it looks like one, so a
 * hostile key cannot put markup or a paragraph into our error message.
 */
const FIELD_NAME_RE = /^[A-Za-z0-9_.\-]{1,64}$/;

/**
 * What to answer for a direct-only model the enclave could not serve.
 *
 * `skipped` / `failed` are the lists the candidate loop already keeps. A skip
 * means the attempt was never made; a failure means it was made and the
 * upstream said no. They are kept apart because "retry in a moment" is not the
 * same answer as "your request asked for something this model cannot do".
 *
 * @param {{model: string, provider: string, skipped: Array<{provider:string,reason:string,field?:string}>,
 *          failed: Array<{provider:string,status?:number}>, supportsImages?: boolean}} input
 * @returns {{status:number,type:string,code:string,message:string}}
 */
export function classifyDirectOnlyRefusal({ model, provider, skipped, failed, supportsImages }) {
  const failure = (failed || []).find((f) => f.provider === provider);
  if (failure) {
    const s = failure.status;
    if (s === 429) return rateLimited(model);
    // Ours, not the caller's: the allowlist drifted (400/422) or the wire
    // model id is wrong (404). Loud and not worth retrying.
    if (s === 400 || s === 404 || s === 422) return upstreamError(model);
    // 401/403 is OUR key being rejected — an outage from the caller's side —
    // and everything else is the upstream being down or slow.
    return unavailable(model);
  }

  const skip = (skipped || []).find((s) => s.provider === provider);
  // hp offered no candidate for this provider at all: it is off, or the id is
  // not published. Neither clears on a retry.
  if (!skip) return notFound(model);

  if (UNAVAILABLE_REASONS.has(skip.reason)) return unavailable(model);
  if (skip.reason === 'model_not_in_catalog') return notFound(model);

  const message = UNSUPPORTED_MESSAGES[skip.reason];
  // A reason this table does not know: say the request cannot be served
  // rather than invent advice, and never fall through to OpenRouter.
  if (!message) return unsupported(`The model "${model}" cannot be served for this request.`);
  const field = typeof skip.field === 'string' && FIELD_NAME_RE.test(skip.field) ? skip.field : undefined;
  return unsupported(message(model, field, { supportsImages: supportsImages === true }));
}
