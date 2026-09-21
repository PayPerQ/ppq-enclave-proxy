// The certificate this process presents when nothing more specific applies,
// and the private key that must sign a receipt on a given connection.
//
// WHY THIS EXISTS (#195)
// ----------------------
// The server used to be built with the boot self-signed certificate as its
// default context and hand the ACME certificate out of SNICallback. That reads
// as "SNI picks the certificate", and for TLS 1.3 it did. It is not what
// OpenSSL does: the context SNICallback returns is ADDED to the connection, the
// default's certificate stays selectable, and the CLIENT's cipher-suite order
// decides between them. The boot certificate was RSA, the ACME one is P-256,
// and every client that lists ECDHE-RSA ahead of ECDHE-ECDSA -- which is TLS
// 1.2 on Windows Schannel, among others -- was served the self-signed
// certificate for api.ppq.ai and failed validation. TLS 1.3 negotiates by
// signature algorithm, where OpenSSL clients list ECDSA first, so curl, Node
// and every browser saw the right certificate and nobody noticed.
//
// The fix is to stop offering the boot certificate at all once a real one is
// held: the issued certificate BECOMES the default context. The boot
// certificate then exists only until the first install, which is the window
// it was made for.
//
// The signing key has to move with it. A receipt is verified against the SPKI
// of the certificate the peer actually saw (connectionSpki, #112); a lookup by
// SNI would keep signing with the boot key on any connection whose name has
// no issued certificate -- a bare-IP client, say -- while that connection is
// now served the issued one. So the key is found by the served certificate's
// SPKI, which cannot disagree with the attestation by construction.
import { X509Certificate, createHash, createPrivateKey } from 'node:crypto';

/** A certificate's SubjectPublicKeyInfo, DER (certificate as DER or PEM in). */
export function spkiDer(cert) {
  return new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
}

/** SHA-256 hex of a certificate's SubjectPublicKeyInfo (DER or PEM in). */
export function spkiSha256Hex(cert) {
  return createHash('sha256').update(spkiDer(cert)).digest('hex');
}

/**
 * @param {object} o
 * @param {Buffer|string} o.key   boot private key PEM
 * @param {Buffer|string} o.cert  boot certificate PEM
 * @param {string} [o.minVersion] TLS floor, carried into every context this builds
 * @param {(m: string) => void} [o.log]
 */
export function createServedIdentity({ key, cert, minVersion = 'TLSv1.2', log = () => {} }) {
  if (!key || !cert) throw new Error('servedIdentity: boot key and certificate are required');
  // spki hex -> KeyObject, for every certificate this process may present.
  const keysBySpki = new Map();
  let server = null;
  let current;

  function describe(creds) {
    const der = spkiDer(creds.cert);
    return {
      key: creds.key,
      cert: creds.cert,
      spki: createHash('sha256').update(der).digest('hex'),
      spkiB64: Buffer.from(der).toString('base64'),
    };
  }
  current = describe({ key, cert });
  keysBySpki.set(current.spki, createPrivateKey(key));
  const bootSpki = current.spki;

  /** Options for tls/https createServer, or for setSecureContext: the current default. */
  function contextOptions() {
    return { key: current.key, cert: current.cert, minVersion };
  }

  return {
    contextOptions,

    /**
     * The server whose default context follows adopt(). The server is created
     * from contextOptions(), so it is current at attach time whatever the order
     * of adopt() and creation; nothing is re-applied here (setSecureContext
     * mints fresh session-ticket keys, so a redundant call is not free).
     */
    attach(s) {
      server = s;
    },

    /**
     * An issued certificate is now held: present it by default and sign with
     * its key. Idempotent for the certificate already current. Applies to the
     * attached server immediately; if none is attached yet, the next
     * contextOptions() carries it, so the order of install and listen does
     * not matter (workers receive MSG.ISSUED before they create their server).
     */
    adopt(creds) {
      if (!creds?.key || !creds?.cert) return false;
      const next = describe(creds);
      if (next.spki === current.spki && String(creds.cert) === String(current.cert)) return false;
      // Everything that can fail happens BEFORE anything is committed: a key
      // that does not parse, or a context OpenSSL rejects, must leave the
      // registry, `current` and the wire exactly as they were -- so /health
      // keeps reporting the boot certificate and the same credentials can be
      // retried. Committing first would have the identity SIGN with a key
      // whose certificate is not being served, the #112 divergence.
      const keyObject = createPrivateKey(creds.key);
      if (server) server.setSecureContext({ key: next.key, cert: next.cert, minVersion });
      if (!keysBySpki.has(next.spki)) keysBySpki.set(next.spki, keyObject);
      current = next;
      return true;
    },

    /**
     * The private key for the certificate a connection was actually served,
     * given `socket.getCertificate()`.
     *
     * A served certificate this identity does not hold returns NULL, never a
     * guess: the caller signs nothing rather than sign with a key the
     * attestation did not commit to (#112). When the socket cannot say what
     * it served (no certificate object, or one that does not parse -- a test
     * double), the answer is the current default's key, which is exactly the
     * fallback connectionSpki makes for the same socket, so the two agree.
     */
    signingKeyFor(peerCert) {
      if (peerCert?.raw) {
        let hex;
        try {
          hex = spkiSha256Hex(peerCert.raw);
        } catch {
          return keysBySpki.get(current.spki);
        }
        return keysBySpki.get(hex) || null;
      }
      return keysBySpki.get(current.spki);
    },

    /** For /health and tests: what is on the wire by default right now. */
    currentSpkiSha256() {
      return current.spki;
    },
    /** The default's SPKI as the attestation reports it: the fallback for a socket that cannot say what it served. */
    currentSpki() {
      return { hex: current.spki, b64: current.spkiB64 };
    },
    /** True until the first adopt(): the boot self-signed certificate is the default. */
    isBoot() {
      return current.spki === bootSpki;
    },
  };
}
