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

/** SHA-256 hex of a certificate's SubjectPublicKeyInfo (DER or PEM in). */
export function spkiSha256Hex(cert) {
  const der = new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
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

  function register(creds) {
    const hex = spkiSha256Hex(creds.cert);
    if (!keysBySpki.has(hex)) keysBySpki.set(hex, createPrivateKey(creds.key));
    return hex;
  }
  function setCurrent(creds, hex) {
    current = { key: creds.key, cert: creds.cert, spki: hex };
  }
  setCurrent({ key, cert }, register({ key, cert }));
  const bootSpki = current.spki;

  /** Options for tls/https createServer, or for setSecureContext: the current default. */
  function contextOptions() {
    return { key: current.key, cert: current.cert, minVersion };
  }

  return {
    contextOptions,

    /** The server whose default context follows adopt(). Safe to call before or after adopt(). */
    attach(s) {
      server = s;
      // Creation uses contextOptions() and so is already current. Re-applying
      // covers a server built some other way; while the boot pair is current
      // there is nothing to apply.
      if (current.spki === bootSpki) return;
      try {
        s.setSecureContext(contextOptions());
      } catch (e) {
        log(`served-identity: could not apply the current certificate to the server: ${e.message}`);
      }
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
      const hex = register(creds);
      if (hex === current.spki && String(creds.cert) === String(current.cert)) return false;
      setCurrent(creds, hex);
      if (server) {
        try {
          server.setSecureContext(contextOptions());
        } catch (e) {
          log(`served-identity: setSecureContext failed; the previous certificate stays on the wire: ${e.message}`);
          return false;
        }
      }
      return true;
    },

    /**
     * The private key for the certificate a connection was actually served,
     * given `socket.getCertificate()`. Falls back to the current default's key
     * when the socket cannot say (a non-TLS socket in tests), never to a key
     * for a certificate this process does not hold.
     */
    signingKeyFor(peerCert) {
      try {
        if (peerCert?.raw) {
          const k = keysBySpki.get(spkiSha256Hex(peerCert.raw));
          if (k) return k;
        }
      } catch {
        // fall through to the default: an unparsable certificate object is a
        // test double, not a served certificate
      }
      return keysBySpki.get(current.spki);
    },

    /** For /health and tests: what is on the wire by default right now. */
    currentSpkiSha256() {
      return current.spki;
    },
    /** True until the first adopt(): the boot self-signed certificate is the default. */
    isBoot() {
      return current.spki === bootSpki;
    },
  };
}
