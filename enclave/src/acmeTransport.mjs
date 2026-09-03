// A fetch-shaped adapter that reaches an ACME directory through the enclave's
// vsock tunnels.
//
// The enclave has no network interface. Every outbound request goes to a
// loopback port that a host-side vsock-proxy forwards to one pinned
// destination, and TLS is validated end-to-end against the REAL hostname from
// in here -- so the parent forwards bytes and cannot read or redirect them. A
// misdirected tunnel fails the handshake rather than silently serving something
// else.
//
// Written rather than using global fetch because fetch offers no way to say
// "connect to 127.0.0.1:9451 but validate the certificate for
// acme-staging-v02.api.letsencrypt.org", which is exactly the shape every
// upstream in this proxy needs.
//
// Returns the small subset of the Response interface AcmeClient uses, so the
// client stays testable against an ordinary fetch mock.

import https from 'node:https';

/**
 * @param {Record<string, number>} tunnels hostname -> loopback port
 */
export function createAcmeFetch(tunnels) {
  return function acmeFetch(url, init = {}) {
    const u = new URL(url);
    const port = tunnels[u.hostname];
    if (!port) {
      return Promise.reject(
        new Error(`no vsock tunnel for ${u.hostname} (have: ${Object.keys(tunnels).join(', ') || 'none'})`),
      );
    }
    const body = init.body ? Buffer.from(init.body) : null;
    const headers = { ...(init.headers || {}), host: u.hostname };
    if (body) headers['content-length'] = Buffer.byteLength(body);

    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port,
          // The name the certificate is checked against. The host cannot
          // substitute an endpoint without failing this.
          servername: u.hostname,
          method: init.method || 'GET',
          path: u.pathname + u.search,
          headers,
          timeout: 60000,
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              headers: {
                // ACME reads replay-nonce and location; node lowercases keys.
                get: (name) => res.headers[String(name).toLowerCase()] ?? null,
              },
              text: async () => text,
              json: async () => JSON.parse(text),
            });
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('acme request timeout')));
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  };
}
