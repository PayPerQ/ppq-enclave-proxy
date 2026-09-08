/**
 * EHBP (Encrypted HTTP Body Protocol) recipient — the server/enclave side.
 *
 * The browser reuses PayPerQ's bundled `ehbp` client to HPKE-seal the request
 * body to this enclave's public key; only the enclave (holding the private key)
 * can decrypt. This is what keeps the query content invisible to the host even
 * though the host terminates the browser's TLS.
 *
 * `ehbp` ships only the CLIENT (encrypt request / decrypt response). This module
 * is the matching recipient, built from the SAME `hpke` + `@panva/hpke-noble`
 * primitives and reusing `ehbp`'s own `deriveResponseKeys`/`encryptChunk` so the
 * wire format is byte-identical to the client.
 *
 * Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
 * Request  wire: header `Ehbp-Encapsulated-Key: <hex enc>` + body `[u32 BE len][HPKE seal]`.
 * Response wire: header `Ehbp-Response-Nonce: <hex 32B>` + frames `[u32 BE len][encryptChunk]`.
 *
 * IDENTITY PERSISTENCE (#52 scaling)
 * ----------------------------------
 * The keypair used to be generated per process and forgotten. That is fine for
 * one enclave that never restarts, and wrong for everything else: a browser
 * attests on one connection and seals on the next, so any key that changes
 * underneath it -- a restart, a second box behind a load balancer, a cluster
 * worker -- turns into a failed request. `toJSON`/`fromJSON` let the identity
 * ride inside the KMS-sealed store next to the certificate, so every process
 * that can unseal the store presents the SAME public key. The JSON carries the
 * PRIVATE key: it must only ever be handed to `sealStore`, never logged.
 */

import { randomBytes } from 'node:crypto';
import { CipherSuite } from 'hpke';
import {
  KEM_DHKEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM,
} from '@panva/hpke-noble';
import {
  deriveResponseKeys,
  encryptChunk,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  RESPONSE_NONCE_LENGTH,
} from 'ehbp';

const enc = new TextEncoder();

/**
 * Names the suite a stored identity was made for. Checked on the way back in
 * so a blob from a future suite change is refused rather than misparsed.
 */
export const HPKE_SUITE_ID = 'dhkem-x25519-hkdf-sha256/hkdf-sha256/aes-256-gcm';
/** Bumped only if the serialised identity layout changes. */
export const HPKE_IDENTITY_VERSION = 1;

const HEX_32 = /^[0-9a-f]{64}$/;
const hex = (u8) => Buffer.from(u8).toString('hex');

export class EhbpRecipient {
  constructor(suite, publicKey, privateKey) {
    this.suite = suite;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static suite() {
    return new CipherSuite(
      KEM_DHKEM_X25519_HKDF_SHA256,
      KDF_HKDF_SHA256,
      AEAD_AES_256_GCM,
    );
  }

  /** Generate a fresh HPKE keypair for this enclave process. */
  static async generate() {
    const suite = EhbpRecipient.suite();
    // Extractable: the identity has to be serialisable into the sealed store.
    const { publicKey, privateKey } = await suite.GenerateKeyPair(true);
    return new EhbpRecipient(suite, publicKey, privateKey);
  }

  /**
   * Serialise for the sealed store. CONTAINS THE PRIVATE KEY -- the only
   * legitimate consumer is `sealStore`.
   */
  async toJSON() {
    return {
      v: HPKE_IDENTITY_VERSION,
      suite: HPKE_SUITE_ID,
      publicKey: hex(await this.suite.SerializePublicKey(this.publicKey)),
      privateKey: hex(await this.suite.SerializePrivateKey(this.privateKey)),
    };
  }

  /**
   * Restore an identity produced by `toJSON`.
   *
   * Throws on anything unexpected rather than returning a half-usable
   * recipient. The last check is a seal/open round trip: a public key that
   * does not belong to the private key is exactly the failure that would
   * otherwise surface as "every browser request fails to decrypt", and only
   * after the attestation had already advertised the wrong key.
   */
  static async fromJSON(obj) {
    if (!obj || typeof obj !== 'object') throw new Error('hpke identity is not an object');
    if (obj.v !== HPKE_IDENTITY_VERSION) throw new Error(`unsupported hpke identity version ${obj.v}`);
    if (obj.suite !== HPKE_SUITE_ID) throw new Error(`unsupported hpke suite ${obj.suite}`);
    for (const field of ['publicKey', 'privateKey']) {
      if (typeof obj[field] !== 'string' || !HEX_32.test(obj[field])) {
        throw new Error(`hpke identity ${field} is not 32 bytes of hex`);
      }
    }
    const suite = EhbpRecipient.suite();
    const publicKey = await suite.DeserializePublicKey(new Uint8Array(Buffer.from(obj.publicKey, 'hex')));
    const privateKey = await suite.DeserializePrivateKey(new Uint8Array(Buffer.from(obj.privateKey, 'hex')), true);

    const info = enc.encode(HPKE_REQUEST_INFO);
    const probe = enc.encode('ppq-hpke-identity-probe');
    try {
      const { encapsulatedSecret, ctx } = await suite.SetupSender(publicKey, { info });
      const sealed = await ctx.Seal(probe);
      const rctx = await suite.SetupRecipient(privateKey, encapsulatedSecret, { info });
      const opened = await rctx.Open(sealed);
      if (Buffer.compare(Buffer.from(opened), Buffer.from(probe)) !== 0) throw new Error('probe mismatch');
    } catch (e) {
      throw new Error(`hpke identity keypair does not match (${e.message})`);
    }
    return new EhbpRecipient(suite, publicKey, privateKey);
  }

  /** Raw 32-byte X25519 public key, hex — committed inside the attestation. */
  async publicKeyHex() {
    const raw = await this.suite.SerializePublicKey(this.publicKey);
    return Buffer.from(raw).toString('hex');
  }

  /**
   * Decrypt an EHBP request.
   * @param {string} encapKeyHex  value of the Ehbp-Encapsulated-Key header
   * @param {Buffer} body         `[u32 BE len][HPKE-sealed ciphertext]`
   * @returns {{plaintext: Buffer, exportedSecret: Uint8Array, requestEnc: Uint8Array}}
   */
  async openRequest(encapKeyHex, body) {
    const requestEnc = new Uint8Array(Buffer.from(encapKeyHex, 'hex'));
    if (body.length < 4) throw new Error('EHBP body too short');
    const len = body.readUInt32BE(0);
    if (body.length < 4 + len) throw new Error('EHBP body length mismatch');
    const sealed = new Uint8Array(body.subarray(4, 4 + len));

    const ctx = await this.suite.SetupRecipient(this.privateKey, requestEnc, {
      info: enc.encode(HPKE_REQUEST_INFO),
    });
    const plaintext = await ctx.Open(sealed);
    const exportedSecret = new Uint8Array(
      await ctx.Export(enc.encode(EXPORT_LABEL), EXPORT_LENGTH),
    );
    return { plaintext: Buffer.from(plaintext), exportedSecret, requestEnc };
  }

  /**
   * Build a streaming response encryptor bound to this request's HPKE context.
   * @returns {Promise<{responseNonceHex: string, encrypt: (chunk: Buffer|Uint8Array) => Promise<Buffer>}>}
   */
  async responseEncryptor(exportedSecret, requestEnc) {
    const responseNonce = new Uint8Array(randomBytes(RESPONSE_NONCE_LENGTH));
    const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);
    let seq = 0;
    return {
      responseNonceHex: Buffer.from(responseNonce).toString('hex'),
      encrypt: async (chunk) => {
        const ct = await encryptChunk(km, seq++, new Uint8Array(chunk));
        const frame = Buffer.alloc(4 + ct.length);
        frame.writeUInt32BE(ct.length, 0);
        Buffer.from(ct).copy(frame, 4);
        return frame;
      },
    };
  }
}
