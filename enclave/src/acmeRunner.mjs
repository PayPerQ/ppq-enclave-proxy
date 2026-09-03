// Drives an ACME order to completion and holds the challenge certificate the
// TLS server must present while it is in flight.
//
// SEPARATE FROM acme.mjs ON PURPOSE: that file is the protocol, and is testable
// without a network or a TLS server. This one owns the mutable state the server
// has to consult on every handshake, and the decision of when to do anything.
//
// HOW THE CHALLENGE IS ANSWERED
// -----------------------------
// RFC 8737 validation is a TLS handshake to port 443 for the domain, with ALPN
// `acme-tls/1`. The server must answer THAT handshake with a self-signed
// certificate carrying the key authorization digest, and answer every other
// handshake normally. Two hooks do it:
//
//   ALPNCallback  negotiates acme-tls/1 ONLY when a challenge is pending for
//                 that SNI, so an ordinary client never gets it
//   SNICallback   returns the challenge certificate for that name while the
//                 challenge is pending, and the real one otherwise
//
// The pairing matters. Presenting the challenge certificate to a normal client
// would break it; negotiating acme-tls/1 without the matching certificate fails
// the challenge with no useful diagnostic.
//
// STAGING BY DEFAULT. Let's Encrypt production has a 5-duplicate-certificates
// per week ceiling and no way to undo a burn; staging has generous limits and
// issues untrusted certificates, which is exactly what an unproven client
// should be pointed at. Production requires an explicit opt-in.

import { AcmeClient, LETSENCRYPT_STAGING, generateAccountKey, generateCertKey,
         keyAuthorization, makeChallengeCert, makeCsr, pollUntil } from './acme.mjs';

/** Challenge certificates by SNI name, live only while an order is running. */
const pendingChallenges = new Map();

/** Whether a handshake for this name should be answered as a challenge. */
export function hasPendingChallenge(servername) {
  return typeof servername === 'string' && pendingChallenges.has(servername);
}

/** The challenge certificate for a name, or undefined. */
export function challengeCredentials(servername) {
  return pendingChallenges.get(servername);
}

/**
 * ALPN selection for the enclave's TLS server.
 *
 * Deliberately conservative for everything that is not a challenge: this server
 * speaks HTTP/1.1 only, and before this hook existed Node negotiated no ALPN at
 * all, so clients simply proceeded over HTTP/1.1. Returning `http/1.1` whenever
 * it is offered preserves that. `undefined` rejects the connection, which is
 * correct for a client that offers only h2 -- this server cannot serve it -- but
 * that client was already broken here, so nothing regresses.
 */
export function selectAlpn({ servername, protocols }) {
  const list = Array.isArray(protocols) ? protocols : [];
  if (list.includes('acme-tls/1') && hasPendingChallenge(servername)) return 'acme-tls/1';
  if (list.includes('http/1.1')) return 'http/1.1';
  return undefined;
}

/**
 * Obtain a certificate for `domain` over TLS-ALPN-01.
 *
 * Returns { key, cert } on success. Throws on failure -- the caller decides
 * whether that is fatal, and for a shadow hostname it is not.
 *
 * @param {object} o
 * @param {string} o.domain
 * @param {(url: string, init?: object) => Promise<Response>} o.fetchImpl vsock-tunnelled
 * @param {string} [o.directoryUrl] defaults to Let's Encrypt STAGING
 * @param {string} [o.contactEmail]
 * @param {object} [o.log]
 */
export async function obtainCertificate({
  domain,
  fetchImpl,
  directoryUrl = LETSENCRYPT_STAGING,
  contactEmail,
  accountKey,
  log = () => {},
}) {
  const key = accountKey || generateAccountKey().privateKey;
  const client = new AcmeClient({ directoryUrl, accountKey: key, fetchImpl });

  log(`acme: registering against ${directoryUrl}`);
  await client.register(contactEmail);

  log(`acme: ordering ${domain}`);
  const { order, url: orderUrl } = await client.newOrder([domain]);

  for (const authzUrl of order.authorizations || []) {
    const { challenge } = await client.tlsAlpnChallenge(authzUrl);
    const keyAuth = keyAuthorization(challenge.token, key);
    // Install BEFORE accepting: the CA may validate the instant it is told to,
    // and a challenge certificate that arrives late fails the order outright.
    pendingChallenges.set(domain, makeChallengeCert(domain, keyAuth));
    log(`acme: challenge armed for ${domain}`);
    try {
      await client.acceptChallenge(challenge.url);
      await pollUntil(
        () => client.fetchResource(authzUrl),
        (a) => a.status === 'valid' || a.status === 'invalid',
        { attempts: 20, intervalMs: 3000 },
      ).then((a) => {
        if (a.status !== 'valid') {
          throw new Error(`authorization ${a.status}: ${JSON.stringify(a.challenges?.[0]?.error || {})}`);
        }
      });
    } finally {
      // Always disarm. Leaving it installed would make the shadow hostname keep
      // serving a certificate no ordinary client can use.
      pendingChallenges.delete(domain);
    }
  }

  log('acme: finalizing');
  const certKeyPair = generateCertKey();
  const csr = makeCsr(domain, certKeyPair.privateKey);
  await client.finalize(order.finalize, csr);
  const done = await pollUntil(
    () => client.fetchResource(orderUrl),
    (o) => o.status === 'valid' || o.status === 'invalid',
    { attempts: 20, intervalMs: 3000 },
  );
  if (done.status !== 'valid') throw new Error(`order ${done.status}`);

  const chain = await client.downloadCertificate(done.certificate);
  log(`acme: issued ${chain.length} bytes for ${domain}`);
  return {
    key: certKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    cert: chain,
  };
}

/** Tests only. */
export function __setPendingChallenge(domain, creds) {
  if (creds) pendingChallenges.set(domain, creds);
  else pendingChallenges.delete(domain);
}
