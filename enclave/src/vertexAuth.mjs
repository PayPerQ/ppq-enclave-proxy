/**
 * Vertex OAuth token minting — the in-enclave half of `key_ref: 'vertex'`.
 *
 * Every other direct provider presents a static bearer key; Vertex wants a
 * short-lived OAuth2 access token minted from a service-account key. The SA
 * key (base64 JSON, same encoding as horse-power's VERTEX_SA_KEY_JSON)
 * arrives via the init blob like the other secrets; ONLY the minted token
 * ever goes on the wire, and only to Google's own token endpoint through its
 * dedicated vsock tunnel.
 *
 * Dependency-free by design (the enclave image carries no google-auth-library;
 * precedent: sigv4.mjs hand-rolls request signing): the mint is an RS256-signed
 * JWT (node:crypto) POSTed as a jwt-bearer grant. Tokens are cached to
 * expiry−5min and minting is single-flight — concurrent candidates await one
 * exchange rather than stampeding the endpoint.
 *
 * Failure posture, same as every credential here: any problem (bad key blob,
 * tunnel down, endpoint error) resolves to null, the connector skips the
 * vertex candidate (`no_tunnel_or_key`), and the request falls back to
 * OpenRouter. A malicious host can deny Vertex, never break a request.
 */
import https from 'node:https';
import { createSign } from 'node:crypto';

const OAUTH_HOST = 'oauth2.googleapis.com';
const OAUTH_PATH = '/token';
const SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const AUDIENCE = `https://${OAUTH_HOST}${OAUTH_PATH}`;
const TOKEN_TTL_SECONDS = 3600;
const EXPIRY_MARGIN_MS = 5 * 60 * 1000;
const MINT_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

const b64url = (input) =>
  Buffer.from(input).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

/** Default transport: POST the form through the oauth vsock tunnel. */
function tunnelTransport({ port, formBody }) {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        servername: OAUTH_HOST,
        method: 'POST',
        path: OAUTH_PATH,
        headers: {
          host: OAUTH_HOST,
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(formBody),
        },
        timeout: MINT_TIMEOUT_MS,
      },
      (res) => {
        let size = 0;
        const parts = [];
        res.on('data', (d) => {
          size += d.length;
          if (size > MAX_RESPONSE_BYTES) {
            res.destroy();
            resolve({ statusCode: res.statusCode, body: '' });
            return;
          }
          parts.push(d);
        });
        res.on('end', () =>
          resolve({ statusCode: res.statusCode, body: Buffer.concat(parts).toString('utf8') }),
        );
        res.on('error', () => resolve({ statusCode: 0, body: '' }));
      },
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve({ statusCode: 0, body: '' }));
    req.write(formBody);
    req.end();
  });
}

export class VertexTokenMinter {
  /**
   * @param saKeyJson base64-encoded service-account key JSON ('' = inert)
   * @param oauthPort in-enclave tunnel port to oauth2.googleapis.com (0 = inert)
   * @param transport injectable for tests; defaults to the vsock tunnel POST
   */
  constructor({ saKeyJson = '', oauthPort = 0, log = () => {}, transport = tunnelTransport } = {}) {
    this.oauthPort = oauthPort;
    this.log = log;
    this.transport = transport;
    this.token = null;
    this.expiresAt = 0;
    this.inflight = null;
    this.sa = null;
    if (saKeyJson) {
      try {
        const parsed = JSON.parse(Buffer.from(saKeyJson, 'base64').toString('utf8'));
        if (
          parsed &&
          typeof parsed.client_email === 'string' &&
          parsed.client_email !== '' &&
          typeof parsed.private_key === 'string' &&
          parsed.private_key !== ''
        ) {
          this.sa = { clientEmail: parsed.client_email, privateKey: parsed.private_key };
        } else {
          // Fixed message: the decoded blob contains the private key, and a
          // parser/validator message must never quote it into the log stream.
          this.log('vertex SA key blob missing client_email/private_key; vertex stays inert');
        }
      } catch {
        this.log('vertex SA key blob is not base64 JSON; vertex stays inert');
      }
    }
  }

  /** Build the signed jwt-bearer assertion. Throws only on signing failure. */
  _assertion(nowSeconds) {
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claims = b64url(
      JSON.stringify({
        iss: this.sa.clientEmail,
        scope: SCOPE,
        aud: AUDIENCE,
        iat: nowSeconds,
        exp: nowSeconds + TOKEN_TTL_SECONDS,
      }),
    );
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${claims}`);
    const signature = signer
      .sign(this.sa.privateKey)
      .toString('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    return `${header}.${claims}.${signature}`;
  }

  /** Cached token, or a fresh mint, or null (→ candidate skips to OpenRouter). */
  async getToken(now = Date.now()) {
    if (!this.sa || !this.oauthPort) return null;
    if (this.token && now < this.expiresAt - EXPIRY_MARGIN_MS) return this.token;
    if (!this.inflight) {
      this.inflight = this._mint(now).finally(() => {
        this.inflight = null;
      });
    }
    return this.inflight;
  }

  async _mint(now) {
    try {
      const assertion = this._assertion(Math.floor(now / 1000));
      const formBody =
        'grant_type=' +
        encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
        '&assertion=' +
        encodeURIComponent(assertion);
      const res = await this.transport({ port: this.oauthPort, formBody });
      if (!res || res.statusCode !== 200) {
        this.log(`vertex token mint failed: HTTP ${res?.statusCode ?? 0}`);
        return null;
      }
      const parsed = JSON.parse(res.body);
      if (typeof parsed.access_token !== 'string' || parsed.access_token === '') {
        this.log('vertex token mint failed: no access_token in response');
        return null;
      }
      const lifetimeSeconds = Number.isFinite(parsed.expires_in)
        ? Number(parsed.expires_in)
        : TOKEN_TTL_SECONDS;
      this.token = parsed.access_token;
      this.expiresAt = now + lifetimeSeconds * 1000;
      this.log(`vertex token minted (expires_in=${lifetimeSeconds}s)`);
      return this.token;
    } catch (err) {
      // err.message can only carry our own strings or JSON.parse noise over
      // the endpoint's response — never key material.
      this.log(`vertex token mint failed: ${err.message}`);
      return null;
    }
  }
}
