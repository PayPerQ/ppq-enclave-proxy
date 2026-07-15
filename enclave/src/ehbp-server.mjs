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

export class EhbpRecipient {
  constructor(suite, publicKey, privateKey) {
    this.suite = suite;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /** Generate a fresh HPKE keypair for this enclave process. */
  static async generate() {
    const suite = new CipherSuite(
      KEM_DHKEM_X25519_HKDF_SHA256,
      KDF_HKDF_SHA256,
      AEAD_AES_256_GCM,
    );
    const { publicKey, privateKey } = await suite.GenerateKeyPair(true);
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
