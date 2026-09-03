// In-enclave ACME (RFC 8555) over TLS-ALPN-01 (RFC 8737).
//
// WHY THIS EXISTS
// ---------------
// On the public path nginx holds the enclave.ppq.ai private key and terminates
// the client's TLS, so host-blindness rests entirely on the EHBP seal. That
// makes client-side encryption mandatory, which is the adoption barrier: an
// outside developer cannot point the OpenAI SDK at us and get a private
// request without first adopting our HPKE client.
//
// Terminating TLS in here needs no certificate authority at all -- boot.sh
// already generates a key and self-signs it, and the :8443 path has worked that
// way for months. What a CA buys is that ordinary clients accept the connection
// without being told to. So the missing piece is not attested TLS; it is a
// browser-trusted certificate whose private key is generated in here and never
// leaves.
//
// WHY TLS-ALPN-01 AND NOT HTTP-01 OR DNS-01
// -----------------------------------------
// HTTP-01 needs port 80 forwarded in, and DNS-01 needs DNS credentials to live
// inside the enclave -- a standing secret that could rewrite our zone. TLS-ALPN-01
// proves control entirely inside a TLS handshake on 443, the port the enclave is
// going to own anyway. The host forwards bytes and cooperates in no other way,
// which is the whole point.
//
// NO DEPENDENCIES, ON PURPOSE
// ---------------------------
// Anything imported here is measured into PCR0 forever, and this repo's claim is
// that three dependencies and a reproducible build let a stranger verify what
// runs. ACME is a small protocol: sign JSON with a key, walk a state machine.
// Certificate GENERATION is the one thing node:crypto cannot do, so the
// challenge certificate is minted by shelling out to openssl, which the image
// already carries (boot.sh self-signs with it).
//
// STATUS: the pure parts are unit-tested. The order flow has NOT been exercised
// against a live ACME server yet -- see PR for the staging-directory plan.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const LETSENCRYPT_PROD = 'https://acme-v02.api.letsencrypt.org/directory';
export const LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

/** RFC 8737: the certificate for a TLS-ALPN-01 challenge carries this ALPN. */
export const ACME_TLS_ALPN = 'acme-tls/1';

/** id-pe-acmeIdentifier, the critical extension carrying the key authz digest. */
const ACME_IDENTIFIER_OID = '1.3.6.1.5.5.7.1.31';

// ── base64url ────────────────────────────────────────────────────────────────

export function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── account key + JWK ────────────────────────────────────────────────────────

/**
 * ES256 throughout: P-256 keys are small, every ACME CA supports them, and
 * node:crypto signs them without help.
 */
export function generateAccountKey() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/**
 * Public JWK for the account key. Field ORDER matters: the thumbprint is a hash
 * over the canonical JSON, so `crv,kty,x,y` is required by RFC 7638 and is not
 * a style choice.
 */
export function publicJwk(privateKey) {
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
}

/** RFC 7638 thumbprint — the account's stable identity across key formats. */
export function jwkThumbprint(privateKey) {
  const jwk = publicJwk(privateKey);
  return b64u(createHash('sha256').update(JSON.stringify(jwk)).digest());
}

/**
 * Key authorization for a challenge: token || '.' || thumbprint. The CA derives
 * the same string and checks we proved possession of the account key, not just
 * knowledge of a token it handed us in the clear.
 */
export function keyAuthorization(token, privateKey) {
  return `${token}.${jwkThumbprint(privateKey)}`;
}

// ── JWS ──────────────────────────────────────────────────────────────────────

/**
 * Sign an ACME request (RFC 8555 §6.2). `kid` after registration, `jwk` before
 * it — the two are mutually exclusive and the CA rejects both together.
 *
 * ACME requires the raw R||S signature form, which is what node emits for EC
 * with `dsaEncoding: 'ieee-p1363'`. The DER default silently produces a
 * signature every CA rejects, which is the classic first bug in a hand-rolled
 * client.
 */
export function signJws({ payload, protectedHeader, privateKey }) {
  const protectedB64 = b64u(JSON.stringify(protectedHeader));
  const payloadB64 = payload === '' ? '' : b64u(JSON.stringify(payload));
  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`);
  const signature = cryptoSign('sha256', signingInput, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return { protected: protectedB64, payload: payloadB64, signature: b64u(signature) };
}

// ── TLS-ALPN-01 challenge certificate ────────────────────────────────────────

/**
 * DER for the acmeIdentifier extension value: an OCTET STRING wrapping the
 * 32-byte SHA-256 of the key authorization.
 *
 * Hand-rolled rather than pulled from a library because it is exactly six
 * bytes of prefix over a fixed-length digest: 0x04 0x20 then the hash. The
 * outer OCTET STRING that openssl wraps around an extension value is added by
 * openssl itself via the `DER:` form below.
 */
export function acmeIdentifierExtensionValue(keyAuth) {
  const digest = createHash('sha256').update(keyAuth).digest();
  return Buffer.concat([Buffer.from([0x04, 0x20]), digest]);
}

/**
 * Mint the self-signed certificate a TLS-ALPN-01 handshake must present.
 *
 * RFC 8737: subjectAltName is the domain being validated, and the critical
 * acmeIdentifier extension carries SHA-256 of the key authorization. The CA
 * connects with ALPN `acme-tls/1`, reads the extension, and compares.
 *
 * openssl rather than node:crypto because node cannot generate certificates at
 * all, let alone with a custom critical extension. The image already carries
 * openssl for boot.sh's self-signed cert, so this adds nothing to PCR0 beyond
 * this file.
 */
export function makeChallengeCert(domain, keyAuth) {
  const dir = mkdtempSync(join(tmpdir(), 'acme-alpn-'));
  try {
    const extValue = acmeIdentifierExtensionValue(keyAuth).toString('hex').toUpperCase();
    const conf = [
      '[req]',
      'distinguished_name = dn',
      'x509_extensions = ext',
      'prompt = no',
      '[dn]',
      `CN = ${domain}`,
      '[ext]',
      `subjectAltName = DNS:${domain}`,
      // `critical` is mandatory. A non-critical extension makes the CA reject
      // the challenge, and the failure message does not say why.
      `${ACME_IDENTIFIER_OID} = critical,DER:${extValue}`,
    ].join('\n');
    const confPath = join(dir, 'openssl.cnf');
    const keyPath = join(dir, 'key.pem');
    const certPath = join(dir, 'cert.pem');
    writeFileSync(confPath, conf);
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-days', '1', '-config', confPath,
      '-keyout', keyPath, '-out', certPath,
    ], { stdio: 'pipe' });
    return { key: readFileSync(keyPath, 'utf8'), cert: readFileSync(certPath, 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── HTTP plumbing ────────────────────────────────────────────────────────────

/**
 * The enclave has no NIC, so every outbound request is tunnelled through a
 * host-side vsock-proxy. The caller supplies a fetch-like function bound to the
 * right tunnel rather than this module reaching for the network itself, which
 * also makes the order flow testable without one.
 */
export class AcmeClient {
  /**
   * @param {object} o
   * @param {string} o.directoryUrl
   * @param {object} o.accountKey  node KeyObject (private)
   * @param {(url: string, init?: object) => Promise<Response>} o.fetchImpl
   */
  constructor({ directoryUrl, accountKey, fetchImpl }) {
    this.directoryUrl = directoryUrl;
    this.accountKey = accountKey;
    this.fetch = fetchImpl;
    this.directory = null;
    this.nonce = null;
    this.kid = null;
  }

  async loadDirectory() {
    if (this.directory) return this.directory;
    const res = await this.fetch(this.directoryUrl);
    if (!res.ok) throw new Error(`ACME directory ${res.status}`);
    this.directory = await res.json();
    return this.directory;
  }

  /**
   * Nonces are single-use and every response carries a fresh one, so the happy
   * path never spends a round trip on newNonce after the first request.
   */
  async takeNonce() {
    if (this.nonce) {
      const n = this.nonce;
      this.nonce = null;
      return n;
    }
    const dir = await this.loadDirectory();
    const res = await this.fetch(dir.newNonce, { method: 'HEAD' });
    return res.headers.get('replay-nonce');
  }

  async post(url, payload) {
    const nonce = await this.takeNonce();
    const protectedHeader = { alg: 'ES256', nonce, url };
    if (this.kid) protectedHeader.kid = this.kid;
    else protectedHeader.jwk = publicJwk(this.accountKey);

    const body = signJws({ payload, protectedHeader, privateKey: this.accountKey });
    const res = await this.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/jose+json' },
      body: JSON.stringify(body),
    });
    const replay = res.headers.get('replay-nonce');
    if (replay) this.nonce = replay;
    return res;
  }

  /** Register (or recover) the account. Idempotent per account key. */
  async register(contactEmail) {
    const dir = await this.loadDirectory();
    const payload = { termsOfServiceAgreed: true };
    if (contactEmail) payload.contact = [`mailto:${contactEmail}`];
    const res = await this.post(dir.newAccount, payload);
    if (!res.ok && res.status !== 200 && res.status !== 201) {
      throw new Error(`newAccount ${res.status}: ${await res.text()}`);
    }
    this.kid = res.headers.get('location');
    return this.kid;
  }

  async newOrder(domains) {
    const dir = await this.loadDirectory();
    const res = await this.post(dir.newOrder, {
      identifiers: domains.map((value) => ({ type: 'dns', value })),
    });
    if (!res.ok) throw new Error(`newOrder ${res.status}: ${await res.text()}`);
    return { order: await res.json(), url: res.headers.get('location') };
  }

  /** POST-as-GET: an empty payload, which ACME requires for reads. */
  async fetchResource(url) {
    const res = await this.post(url, '');
    if (!res.ok) throw new Error(`GET ${url} -> ${res.status}: ${await res.text()}`);
    return res.json();
  }

  async tlsAlpnChallenge(authzUrl) {
    const authz = await this.fetchResource(authzUrl);
    const ch = (authz.challenges || []).find((c) => c.type === 'tls-alpn-01');
    if (!ch) throw new Error(`no tls-alpn-01 challenge in ${authzUrl}`);
    return { authz, challenge: ch };
  }

  /** Tell the CA to validate. The challenge cert must already be installed. */
  async acceptChallenge(challengeUrl) {
    const res = await this.post(challengeUrl, {});
    if (!res.ok) throw new Error(`accept ${res.status}: ${await res.text()}`);
    return res.json();
  }

  async finalize(finalizeUrl, csrDer) {
    const res = await this.post(finalizeUrl, { csr: b64u(csrDer) });
    if (!res.ok) throw new Error(`finalize ${res.status}: ${await res.text()}`);
    return res.json();
  }

  async downloadCertificate(certUrl) {
    const res = await this.post(certUrl, '');
    if (!res.ok) throw new Error(`cert ${res.status}: ${await res.text()}`);
    return res.text();
  }
}

/**
 * Poll a resource until it leaves a pending state.
 *
 * Bounded by attempts rather than wall-clock so a caller cannot accidentally
 * wait forever on a CA that never resolves the order.
 */
export async function pollUntil(fetchFn, isDone, { attempts = 20, intervalMs = 3000, sleep } = {}) {
  const wait = sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  let last;
  for (let i = 0; i < attempts; i += 1) {
    last = await fetchFn();
    if (isDone(last)) return last;
    await wait(intervalMs);
  }
  throw new Error(`still not done after ${attempts} attempts: ${JSON.stringify(last)}`);
}

/**
 * The TLS key the certificate will be issued for. Generated here and never
 * written anywhere the host can read — that property, not the CA signature, is
 * what makes the host blind.
 */
export function generateCertKey() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/** CSR in DER, via openssl for the same reason as the challenge certificate. */
export function makeCsr(domain, privateKey) {
  const dir = mkdtempSync(join(tmpdir(), 'acme-csr-'));
  try {
    const keyPath = join(dir, 'key.pem');
    const csrPath = join(dir, 'csr.der');
    const confPath = join(dir, 'openssl.cnf');
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(
      confPath,
      ['[req]', 'distinguished_name = dn', 'req_extensions = ext', 'prompt = no',
       '[dn]', `CN = ${domain}`, '[ext]', `subjectAltName = DNS:${domain}`].join('\n'),
    );
    execFileSync('openssl', [
      'req', '-new', '-key', keyPath, '-outform', 'DER', '-out', csrPath, '-config', confPath,
    ], { stdio: 'pipe' });
    return readFileSync(csrPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
