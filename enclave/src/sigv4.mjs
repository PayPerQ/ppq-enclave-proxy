/**
 * AWS Signature Version 4 — dependency-free (node:crypto only), house style.
 *
 * Written for the Bedrock direct upstream (the OpenAI Responses API on
 * bedrock-mantle — service name 'bedrock-mantle'): the enclave holds
 * short-lived AWS credentials and must sign each request itself (there is no
 * bearer key, and @aws-sdk/* is deliberately not a dependency — the trusted
 * codebase stays auditable). The construction follows the AWS General
 * Reference "Signature Version 4 signing process" exactly; the unit tests pin
 * it against AWS's own published example vectors.
 *
 * Scope: header-based signing (Authorization header), empty or literal string
 * query, single-chunk payload hash folded into the canonical request (the
 * x-amz-content-sha256 HEADER is an S3 convention Bedrock does not use, and
 * omitting it keeps the construction testable against AWS's published doc
 * vectors, which sign content-type;host;x-amz-date). Bedrock's response
 * streaming needs nothing more — the SIGNED side is the request, and the
 * request body is a single JSON document whose exact bytes (`bodyStr` in
 * server.mjs) are hashed here and written verbatim upstream.
 */
import { createHash, createHmac } from 'node:crypto';

const sha256hex = (data) => createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();

/**
 * RFC 3986 strict percent-encoding: unreserved characters pass, everything
 * else (including '%') is encoded with uppercase hex. Applied per path
 * SEGMENT: AWS requires each segment of the canonical URI to be URI-encoded
 * TWICE for every service except S3 — the wire path arrives single-encoded
 * (hp builds it with encodeURIComponent, e.g. `us.openai.gpt-5.5-v1%3A0`), so
 * encoding the wire segment once more here yields the double-encoded
 * canonical form (`%3A` → `%253A`). Getting this wrong is the classic Bedrock
 * signing failure, because model ids contain ':'.
 */
function uriEncodeSegment(segment) {
  let out = '';
  for (const ch of segment) {
    if (/[A-Za-z0-9\-._~]/.test(ch)) {
      out += ch;
    } else {
      for (const byte of Buffer.from(ch, 'utf8')) {
        out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return out;
}

/** yyyymmddThhmmssZ + yyyymmdd from a Date, per the SigV4 spec. */
export function amzTimestamps(now) {
  const iso = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  return { amzDate: iso, dateStamp: iso.slice(0, 8) };
}

/**
 * Sign one HTTP request. Returns the headers the caller must set — it never
 * mutates inputs and holds no state, so a signature is a pure function of
 * (request, creds, clock).
 *
 * @param {object} args
 * @param {string} args.method   e.g. 'POST'
 * @param {string} args.host     e.g. 'bedrock-runtime.us-east-2.amazonaws.com'
 * @param {string} args.path     wire path, single-URI-encoded (signed double-encoded)
 * @param {string} [args.query]  canonical query string ('' for Bedrock)
 * @param {string|Buffer} args.body  the EXACT bytes that will be written upstream
 * @param {object} [args.signHeaders] extra headers to include in the signature,
 *   e.g. {'content-type': 'application/json'} — lowercase names.
 * @param {string} args.region   SigV4 scope region (must match the host's)
 * @param {string} [args.service='bedrock']
 * @param {object} args.creds    {accessKeyId, secretAccessKey, sessionToken?}
 * @param {Date}   [args.now]    injectable clock for tests
 * @returns {{authorization: string, 'x-amz-date': string,
 *            'x-amz-security-token'?: string}}
 */
export function signRequest({
  method,
  host,
  path,
  query = '',
  body,
  signHeaders = {},
  region,
  service = 'bedrock',
  creds,
  now = new Date(),
}) {
  const { amzDate, dateStamp } = amzTimestamps(now);
  const payloadHash = sha256hex(body ?? '');

  const canonicalUri =
    path === '' ? '/' : path.split('/').map(uriEncodeSegment).join('/');

  // Canonical headers: lowercase names, trimmed values, sorted by name.
  const headerMap = {
    host,
    'x-amz-date': amzDate,
    ...(creds.sessionToken ? { 'x-amz-security-token': creds.sessionToken } : {}),
  };
  for (const [name, value] of Object.entries(signHeaders)) {
    headerMap[name.toLowerCase()] = String(value).trim();
  }
  const signedHeaderNames = Object.keys(headerMap).sort();
  const canonicalHeaders = signedHeaderNames
    .map((name) => `${name}:${String(headerMap[name]).trim()}\n`)
    .join('');
  const signedHeaders = signedHeaderNames.join(';');

  const canonicalRequest = [
    method,
    canonicalUri,
    query,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    sha256hex(canonicalRequest),
  ].join('\n');

  const signingKey = deriveSigningKey(creds.secretAccessKey, dateStamp, region, service);
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  const out = {
    authorization:
      `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    'x-amz-date': amzDate,
  };
  if (creds.sessionToken) out['x-amz-security-token'] = creds.sessionToken;
  return out;
}

/** kSigning = HMAC-chain over date/region/service — exported for the AWS doc vector test. */
export function deriveSigningKey(secretAccessKey, dateStamp, region, service) {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}
