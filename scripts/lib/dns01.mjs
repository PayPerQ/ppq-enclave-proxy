// DNS-01 proof of control over names under a GoDaddy-hosted zone, shared by
// the two CI renewals:
//
//   scripts/renew-cert-dns01.mjs        the enclave's certificate (key in-enclave)
//   scripts/renew-azure-cert-dns01.mjs  the Azure standby's certificate for
//                                       api.ppq.ai (its own key, on the runner)
//
// The function bodies here were MOVED VERBATIM out of renew-cert-dns01.mjs
// (2026-09-17) and wrapped in a factory so the second script could reuse them
// without changing the first one's behaviour. The factory only supplies the
// values the bodies used to close over as module constants (ZONE, GD_TOKEN,
// DNS_SETTLE_S, ORDER_ATTEMPTS, log) plus test seams for the three globals
// they touch (fetch, dns Resolver, setTimeout). Check the move with:
//
//   diff -w <(git show <pre-move>:scripts/renew-cert-dns01.mjs | sed -n '/^async function godaddy/,/^}/p') \
//           <(sed -n '/^  async function godaddy/,/^  }/p' scripts/lib/dns01.mjs)
//
// and likewise for authoritativeResolvers, visibleEverywhere and the order
// loop inside obtainCertificate (see enclave/test/dns01.test.mjs, which pins
// the observable behaviour).
import { Resolver as DnsResolver } from 'node:dns/promises';
import { dnsTxtValue, keyAuthorization, pollUntil as acmePollUntil } from '../../enclave/src/acme.mjs';

/**
 * @param {object} opts
 * @param {string} opts.zone            registered domain the names live under (e.g. 'ppq.ai')
 * @param {string} opts.godaddyToken    GoDaddy API token ('sso-key K:S' or a bearer token)
 * @param {(m: string) => void} opts.log
 * @param {number} [opts.settleSeconds=45]  wait after every nameserver serves the TXT
 * @param {number} [opts.orderAttempts=2]   one retry with a fresh order on a DNS-class failure
 * @param {typeof fetch} [opts.fetchImpl]           test seam
 * @param {typeof DnsResolver} [opts.Resolver]      test seam
 * @param {typeof setTimeout} [opts.setTimeout]     test seam
 */
export function createDns01({
  zone, godaddyToken, log, settleSeconds = 45, orderAttempts = 2,
  fetchImpl, Resolver: ResolverImpl, setTimeout: setTimeoutImpl,
} = {}) {
  if (!zone) throw new Error('createDns01: zone is required');
  if (typeof log !== 'function') throw new Error('createDns01: log is required');
  const ZONE = zone;
  const GD_TOKEN = godaddyToken || '';
  const DNS_SETTLE_S = Number(settleSeconds);
  const ORDER_ATTEMPTS = Number(orderAttempts);
  const fetch = fetchImpl || globalThis.fetch;
  const Resolver = ResolverImpl || DnsResolver;
  const setTimeout = setTimeoutImpl || globalThis.setTimeout;
  // pollUntil sleeps with the real timer unless told otherwise; route an
  // injected timer into it so tests can advance the DNS wait. With no
  // injection the option is undefined and pollUntil behaves exactly as before.
  const pollUntil = (fetchFn, isDone, opts) => acmePollUntil(fetchFn, isDone, {
    ...opts, sleep: setTimeoutImpl ? (ms) => new Promise((r) => setTimeout(r, ms)) : undefined,
  });

  async function godaddy(method, path, body) {
    const r = await fetch(`https://api.godaddy.com/v1/domains/${ZONE}${path}`, {
      method, headers: { authorization: `Bearer ${GD_TOKEN}`, 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    // A DELETE of a record that is already gone is fine; anything else must succeed.
    if (!r.ok && !(method === 'DELETE' && r.status === 404)) throw new Error(`GoDaddy ${method} ${path} -> ${r.status}: ${await r.text()}`);
    return r.status;
  }

  /** One resolver per authoritative nameserver of the zone (all of them). */
  async function authoritativeResolvers() {
    const r = new Resolver();
    const ns = await r.resolveNs(ZONE);
    const out = [];
    for (const n of ns) {
      for (const ip of await r.resolve4(n).catch(() => [])) {
        const one = new Resolver(); one.setServers([ip]); out.push({ ns: n, ip, resolver: one });
      }
    }
    if (!out.length) throw new Error('could not resolve the zone nameservers');
    return out;
  }

  /** True when EVERY authoritative nameserver serves `txt` for `fqdn`. */
  async function visibleEverywhere(resolvers, fqdn, txt) {
    const seen = await Promise.all(resolvers.map(async ({ ns, resolver }) => {
      const v = (await resolver.resolveTxt(fqdn).catch(() => [])).flat();
      return { ns, ok: v.includes(txt) };
    }));
    const missing = seen.filter((x) => !x.ok).map((x) => x.ns);
    return { ok: missing.length === 0, missing };
  }

  /**
   * Prove `names` with DNS-01 on a registered ACME `client`, finalize with
   * `csrDer` and return the PEM chain. Places one TXT per authorization,
   * waits for every authoritative nameserver plus the settle, and on a
   * DNS-class failure retries ONCE with a fresh order (records left in place).
   * TXT records are removed at the very end whatever happened.
   */
  async function obtainCertificate({ client, accountKey, names, csrDer }) {
    const resolvers = await authoritativeResolvers();
    log(`zone nameservers: ${resolvers.map((x) => `${x.ns}(${x.ip})`).join(', ')}`);
    const placed = new Set();
    let order; let orderUrl;
    try {
      for (let attempt = 1; attempt <= ORDER_ATTEMPTS; attempt += 1) {
        ({ order, url: orderUrl } = await client.newOrder(names));
        let dnsFailure = null;
        for (const authzUrl of order.authorizations || []) {
          const { authz, challenge } = await client.dnsChallenge(authzUrl);
          if (authz.status === 'valid') { log(`${authz.identifier.value} already valid`); continue; }
          const name = authz.identifier.value;
          const txt = dnsTxtValue(keyAuthorization(challenge.token, accountKey));
          // _acme-challenge.<label(s)> under the zone; the apex is just
          // _acme-challenge, and a wildcard authz names the base label.
          const bare = name.replace(/^\*\./, '');
          if (bare !== ZONE && !bare.endsWith(`.${ZONE}`)) throw new Error(`${name} is not under ${ZONE}`);
          const rr = bare === ZONE ? '_acme-challenge' : `_acme-challenge.${bare.slice(0, -(ZONE.length + 1))}`;
          await godaddy('PUT', `/records/TXT/${rr}`, [{ data: txt, ttl: 600 }]);
          placed.add(rr);
          log(`TXT ${rr}.${ZONE} = ${txt}`);
          // Every authoritative nameserver, then a settle for the anycast edge.
          await pollUntil(
            () => visibleEverywhere(resolvers, `${rr}.${ZONE}`, txt),
            (v) => v.ok,
            { attempts: 36, intervalMs: 5000 },
          );
          log(`TXT visible at every authoritative nameserver; settling ${DNS_SETTLE_S}s before asking the CA`);
          await new Promise((r) => setTimeout(r, DNS_SETTLE_S * 1000));
          await client.acceptChallenge(challenge.url);
          const done = await pollUntil(() => client.fetchResource(authzUrl), (a) => a.status === 'valid' || a.status === 'invalid', { attempts: 30, intervalMs: 3000 });
          if (done.status !== 'valid') {
            const err = done.challenges?.find((x) => x.type === 'dns-01')?.error || {};
            const msg = `authorization for ${name} ${done.status}: ${JSON.stringify(err)}`;
            if (String(err.type || '').endsWith(':dns') && attempt < ORDER_ATTEMPTS) { dnsFailure = msg; break; }
            throw new Error(msg);
          }
          log(`${name} validated`);
        }
        if (!dnsFailure) break;
        log(`${dnsFailure}\n[renew] DNS-class failure; the records stay in place, retrying with a fresh order in 60s (attempt ${attempt + 1}/${ORDER_ATTEMPTS})`);
        await new Promise((r) => setTimeout(r, 60_000));
      }
    } finally {
      for (const rr of placed) {
        await godaddy('DELETE', `/records/TXT/${rr}`).then((st) => log(`cleaned TXT ${rr} (${st})`)).catch((e) => log(`could not clean TXT ${rr}: ${e.message}`));
      }
    }
    log('finalizing');
    await client.finalize(order.finalize, csrDer);
    const fin = await pollUntil(() => client.fetchResource(orderUrl), (o) => o.status === 'valid' || o.status === 'invalid', { attempts: 30, intervalMs: 3000 });
    if (fin.status !== 'valid') throw new Error(`order ${fin.status}`);
    const chain = await client.downloadCertificate(fin.certificate);
    return chain;
  }

  return { godaddy, authoritativeResolvers, visibleEverywhere, obtainCertificate };
}
