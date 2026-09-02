import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { VertexTokenMinter } from '../src/vertexAuth.mjs';

// A real RSA keypair so the JWT signature can be VERIFIED, not just observed.
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const saB64 = (overrides = {}) =>
  Buffer.from(
    JSON.stringify({
      type: 'service_account',
      client_email: 'hp-vertex@dauntless-arc-443613-n6.iam.gserviceaccount.com',
      private_key: privateKey,
      ...overrides,
    }),
  ).toString('base64');

const b64urlDecode = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

test('mints a verifiable RS256 jwt-bearer grant and caches the token', async () => {
  const calls = [];
  const minter = new VertexTokenMinter({
    saKeyJson: saB64(),
    oauthPort: 9450,
    transport: async ({ port, formBody }) => {
      calls.push({ port, formBody });
      return { statusCode: 200, body: JSON.stringify({ access_token: 'ya29.tok', expires_in: 3600 }) };
    },
  });

  const token = await minter.getToken(1_000_000_000_000);
  assert.equal(token, 'ya29.tok');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].port, 9450);

  const params = new URLSearchParams(calls[0].formBody);
  assert.equal(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  const [h, c, sig] = params.get('assertion').split('.');
  assert.deepEqual(JSON.parse(b64urlDecode(h)), { alg: 'RS256', typ: 'JWT' });
  const claims = JSON.parse(b64urlDecode(c));
  assert.equal(claims.iss, 'hp-vertex@dauntless-arc-443613-n6.iam.gserviceaccount.com');
  assert.equal(claims.scope, 'https://www.googleapis.com/auth/cloud-platform');
  assert.equal(claims.aud, 'https://oauth2.googleapis.com/token');
  assert.equal(claims.exp - claims.iat, 3600);
  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${h}.${c}`);
  assert.equal(verifier.verify(publicKey, b64urlDecode(sig)), true);

  // Cached: a second call within the lifetime mints nothing.
  assert.equal(await minter.getToken(1_000_000_000_000 + 60_000), 'ya29.tok');
  assert.equal(calls.length, 1);
  // Past expiry−margin: re-mints.
  await minter.getToken(1_000_000_000_000 + 3_600_000);
  assert.equal(calls.length, 2);
});

test('concurrent callers share one in-flight mint (single-flight)', async () => {
  let mints = 0;
  let release;
  const gate = new Promise((r) => (release = r));
  const minter = new VertexTokenMinter({
    saKeyJson: saB64(),
    oauthPort: 9450,
    transport: async () => {
      mints++;
      await gate;
      return { statusCode: 200, body: JSON.stringify({ access_token: 't', expires_in: 3600 }) };
    },
  });
  const [a, b] = [minter.getToken(), minter.getToken()];
  release();
  assert.equal(await a, 't');
  assert.equal(await b, 't');
  assert.equal(mints, 1);
});

test('every failure resolves null — never throws (skip → OpenRouter)', async () => {
  // No key / no port → inert without touching the transport.
  const boom = async () => { throw new Error('transport must not be called'); };
  assert.equal(await new VertexTokenMinter({ oauthPort: 9450, transport: boom }).getToken(), null);
  assert.equal(await new VertexTokenMinter({ saKeyJson: saB64(), oauthPort: 0, transport: boom }).getToken(), null);
  // Malformed blobs → inert (and the log line carries no key material).
  const logs = [];
  const log = (m) => logs.push(m);
  assert.equal(
    await new VertexTokenMinter({ saKeyJson: 'not-base64-json!!!', oauthPort: 9450, log, transport: boom }).getToken(),
    null,
  );
  assert.equal(
    await new VertexTokenMinter({ saKeyJson: Buffer.from('{}').toString('base64'), oauthPort: 9450, log, transport: boom }).getToken(),
    null,
  );
  assert.ok(logs.every((l) => !l.includes('PRIVATE KEY')));
  // Endpoint failures → null, and a later call retries.
  let attempt = 0;
  const flaky = new VertexTokenMinter({
    saKeyJson: saB64(),
    oauthPort: 9450,
    transport: async () =>
      ++attempt === 1
        ? { statusCode: 500, body: 'oops' }
        : { statusCode: 200, body: JSON.stringify({ access_token: 'later', expires_in: 3600 }) },
  });
  assert.equal(await flaky.getToken(), null);
  assert.equal(await flaky.getToken(), 'later');
});

// ── vertex usage capture + candidate wiring ─────────────────────────────────
import { CostExtractor } from '../src/cost.mjs';
import { buildDirectRequest } from '../src/upstreams.mjs';

test('CostExtractor captures reasoning_tokens verbatim (Vertex additive convention)', () => {
  const ex = new CostExtractor();
  // The probe-pinned Vertex final chunk shape (vertexUsage.fixtures.json in hp).
  const frame = JSON.stringify({
    model: 'google/gemini-2.5-flash',
    usage: {
      prompt_tokens: 2,
      completion_tokens: 1,
      completion_tokens_details: { reasoning_tokens: 27 },
      total_tokens: 30,
    },
  });
  ex.feed(Buffer.from(`data: ${frame}\n`));
  const usage = ex.finish();
  assert.equal(usage.inputTokens, 2);
  assert.equal(usage.outputTokens, 1);
  assert.equal(usage.reasoningTokens, 27);
});

test('reasoning stays undefined when the provider does not report it', () => {
  const ex = new CostExtractor();
  ex.feed(Buffer.from(`data: ${JSON.stringify({ model: 'm', usage: { prompt_tokens: 5, completion_tokens: 3 } })}\n`));
  assert.equal(ex.finish().reasoningTokens, undefined);
});

test('a vertex candidate skips no_tunnel_or_key without a minted token, builds with one', () => {
  const candidate = {
    provider: 'vertex',
    api_style: 'openai',
    host: 'aiplatform.googleapis.com',
    path: '/v1beta1/projects/p/locations/global/endpoints/openapi/chat/completions',
    key_ref: 'vertex',
    upstream_model: 'google/gemini-2.5-flash',
    or_slug: 'google/gemini-2.5-flash',
    supports_tools: true,
  };
  const basePayload = { model: 'google/gemini-2.5-flash', stream: true, messages: [{ role: 'user', content: 'hi' }] };
  const ports = { 'aiplatform.googleapis.com': 9449 };

  // No token minted → key absent → the documented clean skip.
  const skipped = buildDirectRequest({ candidate, basePayload, ports, keys: { vertex: undefined } });
  assert.equal(skipped.skip, 'no_tunnel_or_key');

  // Minted token → ordinary openai-style build with Bearer injection.
  const built = buildDirectRequest({ candidate, basePayload, ports, keys: { vertex: 'ya29.tok' } });
  assert.equal(built.skip, undefined);
  assert.equal(built.opts.port, 9449);
  assert.equal(built.opts.servername, 'aiplatform.googleapis.com');
  assert.equal(built.opts.headers.authorization, 'Bearer ya29.tok');
  assert.equal(JSON.parse(built.bodyStr).model, 'google/gemini-2.5-flash');
});
