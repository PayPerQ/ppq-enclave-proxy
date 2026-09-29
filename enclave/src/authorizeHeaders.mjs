/**
 * The header set the enclave sends to horse-power `/enclave/authorize`.
 * Pure, so the rule "which client headers reach hp, and what the enclave adds
 * of its own" is testable without the server.
 *
 * Allow-list, not a strip-list: only the named credential/intent headers are
 * copied from the request. In particular a client-supplied `x-ppq-client-ip`
 * or `x-ppq-client-ip-mac` can never reach hp through this path — the only
 * source of that pair is the address the PROXY-protocol listener attached to
 * the socket (`req.socket.clientIp`, proxyListener.mjs), MAC'd with the settle
 * secret exactly as passthrough.mjs does for proxied routes and as
 * horse-power `utils/clientIp.ts` verifies (current or previous minute).
 *
 * `x-request-id` is not copied from the request headers either: it is passed
 * in explicitly as the id the enclave resolved for the request (the client's
 * own `x-request-id` when it sent one, or the `enc-…` one it minted), so hp
 * files an authorize refusal under the same id the receipt, settle and error
 * report use. Bounded to the shape the trace accepts for a correlation id; any
 * other value is left out.
 */
import { enclaveClientIpMac } from './passthrough.mjs';
import { clientRequestId } from './trace.mjs';

// Cleartext credential + intent headers hp parses with the same precedence as
// /chat/completions. `x-ppq-intent` is deliberately forwarded (title requests
// billed to PayPerQ; hp caps model and length, which is what makes it safe).
export const AUTHORIZE_FORWARDED_HEADERS = Object.freeze([
  'authorization',
  'x-api-key',
  'x-credit-id',
  'x-query-source',
  'x-ppq-intent',
]);

/**
 * @param {import('node:http').IncomingHttpHeaders} reqHeaders  the client's request headers
 * @param {object} opts
 * @param {string} opts.host        horse-power host (Host header)
 * @param {number} opts.bodyLength  byte length of the JSON payload
 * @param {string} [opts.clientIp]  address from the PROXY listener, if any
 * @param {string} [opts.secret]    settle secret; empty disables the MAC pair
 * @param {string} [opts.requestId] the id the enclave resolved for this request
 * @param {number} [opts.now]       ms since epoch (injectable for tests)
 */
export function authorizeHeaders(reqHeaders, { host, bodyLength, clientIp, secret, requestId, now = Date.now() }) {
  const headers = {
    'content-type': 'application/json',
    'content-length': bodyLength,
    host,
  };
  for (const name of AUTHORIZE_FORWARDED_HEADERS) {
    const v = reqHeaders?.[name];
    if (typeof v === 'string' && v) headers[name] = v;
  }
  const id = clientRequestId(requestId);
  if (id) headers['x-request-id'] = id;
  if (typeof clientIp === 'string' && clientIp && secret) {
    headers['x-ppq-client-ip'] = clientIp;
    headers['x-ppq-client-ip-mac'] = enclaveClientIpMac(clientIp, Math.floor(now / 60_000), secret);
  }
  return headers;
}
