/**
 * Certificate pinning for the reference verifier (verify.mjs).
 *
 * The verifier trusts nothing about the endpoint until the attestation says
 * so; TLS is only the transport. What it needs from TLS is one property: the
 * server I am talking to NOW presents exactly the certificate whose SPKI the
 * attestation will be checked against. That is a pin on one certificate, not a
 * chain validation.
 *
 * WHY NOT `ca: <leaf PEM>` (the previous implementation, broken 2026-09-21 →
 * 2026-10-19). Passing the fetched leaf as `ca` to https.request asks OpenSSL
 * to treat the leaf as a trust anchor. A self-signed certificate IS its own
 * anchor, so that worked for the bring-up certificate. A Let's Encrypt leaf is
 * not: OpenSSL walks to its issuer, finds no R-series intermediate in the
 * supplied store, and fails with "unable to get local issuer certificate" on
 * every connection. Since #196 made the issued certificate the default TLS
 * context, the verifier has therefore refused every genuine enclave
 * (reported in the Oct 17-19 security reports by haikaljim9; Matt's triage
 * dated it to Sep 21).
 *
 * WHY NOT `checkServerIdentity` alone. Node only calls it when the default
 * chain validation already passed (`_tls_wrap.js` onConnectSecure), and with
 * `rejectUnauthorized: false` its verdict does not abort the connection, it
 * only sets `socket.authorized`. So the check has to be done by hand, after
 * the handshake and BEFORE a single application byte is written.
 *
 * HOW. Connect with `tls.connect`, wait for `secureConnect`, compare the peer
 * certificate's DER bytes to the pinned DER, and only then hand the socket to
 * http.ClientRequest through `createConnection`. The comparison is on the whole
 * certificate, which is stricter than the SPKI the attestation binds; the two
 * agree because the fleet unseals one identity (README: "One EHBP identity"),
 * so every box behind the load balancer presents the same certificate.
 */

import tls from 'node:tls';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';

/** Blind-fetch the peer certificate (DER). Trust is established by the attestation, not here. */
export function fetchPeerCertDer({ host, port, servername, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false }, () => {
      const der = socket.getPeerCertificate(true).raw;
      socket.end();
      resolve(Buffer.from(der));
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error('TLS connect timeout'));
    });
    socket.on('error', reject);
  });
}

/**
 * Open one TLS connection and refuse it unless the peer presents exactly
 * `expectedDer`. Resolves to a connected TLSSocket that has sent nothing yet.
 */
export function connectPinned({ host, port, servername, expectedDer, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false });
    const bail = (err) => {
      socket.destroy();
      reject(err);
    };
    const onConnectTimeout = () => bail(new Error('TLS connect timeout'));
    socket.setTimeout(timeoutMs, onConnectTimeout);
    socket.once('error', bail);
    socket.once('secureConnect', () => {
      const presented = socket.getPeerCertificate(true)?.raw;
      if (!presented || !Buffer.from(presented).equals(expectedDer)) {
        const got = presented ? new X509Certificate(presented).fingerprint256 : 'none';
        const want = new X509Certificate(expectedDer).fingerprint256;
        return bail(
          new Error(
            `certificate pin mismatch: the server presented a different certificate ` +
              `(got ${got.slice(0, 23)}…, pinned ${want.slice(0, 23)}…)`,
          ),
        );
      }
      // The handshake deadline is done; pinnedRequest arms the request-phase
      // one on the same socket (`req.setTimeout`), so there is never a window
      // without a timeout. Both the timer AND its listener go: setTimeout(0)
      // only stops the clock, and a listener left behind would fire alongside
      // the request's own on the next 'timeout', destroying the socket with no
      // error so the caller saw "socket hang up" instead of the deadline.
      socket.setTimeout(0);
      socket.removeListener('timeout', onConnectTimeout);
      socket.removeListener('error', bail);
      resolve(socket);
    });
  });
}

/**
 * Largest response `pinnedRequest` will buffer. The attestation document is a
 * few KB of CBOR plus its JSON wrapper, and the verifier's one chat request
 * asks for 40 tokens; anything far beyond that is not an answer the verifier
 * can use. The bound matters because the FIRST pinned request goes to a server
 * whose only credential so far is "it presented the certificate we just
 * fetched from it" — the attestation has not been checked yet, so that server
 * must not be able to make the verifier buffer without limit.
 */
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/**
 * One HTTPS request over a freshly pinned connection.
 * Returns `{ status, body }`; rejects (and sends nothing) on a pin mismatch.
 *
 * The connection is held to a deadline for its whole life: `connectPinned`
 * bounds the handshake, and `timeoutMs` here bounds every idle gap from the
 * first application byte through the end of the response (`req.setTimeout` is
 * only a notification in Node, so the request is destroyed explicitly). A
 * response that errors after its headers (peer closed mid-body) rejects too:
 * Node emits that on `res`, not `req`, so both are listened for.
 */
export async function pinnedRequest(
  { host, port, servername, expectedDer, timeoutMs = 15_000, maxResponseBytes = MAX_RESPONSE_BYTES },
  path,
  { method = 'GET', headers = {}, body } = {},
) {
  const socket = await connectPinned({ host, port, servername, expectedDer, timeoutMs });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      // One request per pinned connection: close it so the verifier exits
      // instead of idling on the server's keep-alive.
      socket.destroy();
      fn(value);
    };
    const req = https.request(
      {
        host,
        port,
        servername,
        path,
        method,
        headers,
        // No agent (left undefined, NOT `false`: `agent: false` makes Node mint
        // a fresh Agent that opens its own TLS connection and ignores
        // createConnection). The connection is the one we just pinned.
        createConnection: () => socket,
      },
      (res) => {
        const chunks = [];
        let received = 0;
        res.on('data', (c) => {
          received += c.length;
          if (received > maxResponseBytes) {
            req.destroy(new Error(`response exceeded ${maxResponseBytes} bytes`));
            return;
          }
          chunks.push(c);
        });
        res.on('error', (e) => finish(reject, e));
        res.on('end', () => finish(resolve, { status: res.statusCode, body: Buffer.concat(chunks) }));
      },
    );
    req.setHeader('connection', 'close');
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`request timed out after ${timeoutMs} ms`)));
    req.on('error', (e) => finish(reject, e));
    if (body) req.write(body);
    req.end();
  });
}
