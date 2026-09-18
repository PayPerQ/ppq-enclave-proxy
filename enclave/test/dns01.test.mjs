// scripts/lib/dns01.mjs: the DNS-01 flow moved verbatim out of
// scripts/renew-cert-dns01.mjs and now shared with the Azure standby's
// renewal. Pins the observable behaviour of the move -- record naming, the
// every-nameserver wait, cleanup-whatever-happens, and the one retry on a
// DNS-class failure -- with fakes for GoDaddy, DNS and the ACME client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDns01 } from '../../scripts/lib/dns01.mjs';
import { dnsTxtValue, generateAccountKey, keyAuthorization } from '../src/acme.mjs';

const ZONE = 'ppq.ai';
const noop = () => {};
const immediate = (fn) => { fn(); return 0; };

/** A GoDaddy that records calls and answers with `status` (per method). */
function fakeFetch(status = { PUT: 200, DELETE: 204 }) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
    const st = typeof status === 'function' ? status(init.method, url) : status[init.method];
    return { ok: st >= 200 && st < 300, status: st, text: async () => `status ${st}` };
  };
  return { fetch, calls };
}

/** A dns.Resolver whose every server sees the TXT records in `zone`. */
function fakeResolverClass({ ns = ['ns1.test', 'ns2.test'], ips = { 'ns1.test': ['10.0.0.1'], 'ns2.test': ['10.0.0.2', '10.0.0.3'] }, txt = new Map(), blind = new Set() } = {}) {
  class Resolver {
    setServers(servers) { this.server = servers[0]; }
    async resolveNs(zone) { assert.equal(zone, ZONE); return ns; }
    async resolve4(name) { if (!ips[name]) throw new Error('ENOTFOUND'); return ips[name]; }
    async resolveTxt(fqdn) {
      if (blind.has(this.server)) return [];
      const v = txt.get(fqdn); if (!v) throw new Error('ENODATA'); return [[v]];
    }
  }
  return Resolver;
}

/** An ACME client whose authorizations validate according to `outcomes` (per newOrder). */
function fakeClient({ names, outcomes, chain = 'CHAIN-PEM' }) {
  const calls = { newOrder: 0, accepted: [], finalize: null, downloaded: null };
  let orderNo = 0;
  const client = {
    async newOrder(ids) {
      assert.deepEqual(ids, names);
      orderNo = ++calls.newOrder;
      return { order: { authorizations: names.map((n) => `authz:${orderNo}:${n}`), finalize: `finalize:${orderNo}` }, url: `order:${orderNo}` };
    },
    async dnsChallenge(authzUrl) {
      const [, , name] = authzUrl.split(':');
      return { authz: { status: 'pending', identifier: { type: 'dns', value: name } }, challenge: { type: 'dns-01', token: `tok-${name}`, url: `chal:${orderNo}:${name}` } };
    },
    async acceptChallenge(url) { calls.accepted.push(url); return {}; },
    async fetchResource(url) {
      if (url.startsWith('authz:')) {
        const [, o, name] = url.split(':');
        const out = outcomes(Number(o), name);
        return out === 'valid' ? { status: 'valid' } : { status: 'invalid', challenges: [{ type: 'dns-01', error: { type: out } }] };
      }
      if (url.startsWith('order:')) return { status: 'valid', certificate: `cert:${url.split(':')[1]}` };
      throw new Error(`unexpected fetchResource ${url}`);
    },
    async finalize(url, csr) { calls.finalize = { url, csr }; return {}; },
    async downloadCertificate(url) { calls.downloaded = url; return chain; },
  };
  return { client, calls };
}

test('createDns01 requires a zone and a log function', () => {
  assert.throws(() => createDns01({ log: noop }), /zone/);
  assert.throws(() => createDns01({ zone: ZONE }), /log/);
});

test('godaddy: bearer token, JSON body, and a 404 on DELETE is fine', async () => {
  const gd = fakeFetch((method) => (method === 'DELETE' ? 404 : 200));
  const d = createDns01({ zone: ZONE, godaddyToken: 'T', log: noop, fetchImpl: gd.fetch });
  assert.equal(await d.godaddy('PUT', '/records/TXT/_acme-challenge.api', [{ data: 'x', ttl: 600 }]), 200);
  assert.equal(await d.godaddy('DELETE', '/records/TXT/_acme-challenge.api'), 404);
  assert.equal(gd.calls[0].url, 'https://api.godaddy.com/v1/domains/ppq.ai/records/TXT/_acme-challenge.api');
  assert.equal(gd.calls[0].headers.authorization, 'Bearer T');
  assert.deepEqual(gd.calls[0].body, [{ data: 'x', ttl: 600 }]);
  assert.equal(gd.calls[1].body, undefined);
});

test('godaddy: any other failure throws with the status', async () => {
  const gd = fakeFetch(() => 403);
  const d = createDns01({ zone: ZONE, godaddyToken: 'T', log: noop, fetchImpl: gd.fetch });
  await assert.rejects(d.godaddy('PUT', '/records/TXT/x', []), /GoDaddy PUT \/records\/TXT\/x -> 403/);
  await assert.rejects(d.godaddy('DELETE', '/records/TXT/x'), /-> 403/);
});

test('authoritativeResolvers: one resolver per nameserver ADDRESS, skipping unresolvable names', async () => {
  const Resolver = fakeResolverClass({ ns: ['ns1.test', 'ns2.test', 'dead.test'] });
  const d = createDns01({ zone: ZONE, log: noop, Resolver });
  const r = await d.authoritativeResolvers();
  assert.deepEqual(r.map((x) => `${x.ns}@${x.ip}`), ['ns1.test@10.0.0.1', 'ns2.test@10.0.0.2', 'ns2.test@10.0.0.3']);
  assert.ok(r.every((x) => x.resolver.server === x.ip));
});

test('authoritativeResolvers: no address at all is an error', async () => {
  const Resolver = fakeResolverClass({ ns: ['dead.test'] });
  const d = createDns01({ zone: ZONE, log: noop, Resolver });
  await assert.rejects(d.authoritativeResolvers(), /could not resolve the zone nameservers/);
});

test('visibleEverywhere: EVERY nameserver must serve the value; the missing ones are named', async () => {
  const d = createDns01({ zone: ZONE, log: noop });
  const mk = (ns, values) => ({ ns, resolver: { resolveTxt: async () => (values ? [values] : Promise.reject(new Error('ENODATA'))) } });
  assert.deepEqual(await d.visibleEverywhere([mk('a', ['v']), mk('b', ['old', 'v'])], 'f', 'v'), { ok: true, missing: [] });
  assert.deepEqual(await d.visibleEverywhere([mk('a', ['v']), mk('b', ['old']), mk('c', null)], 'f', 'v'), { ok: false, missing: ['b', 'c'] });
});

test('obtainCertificate: places _acme-challenge.<label>, waits for every nameserver, settles, finalizes, cleans up', async () => {
  const accountKey = generateAccountKey().privateKey;
  const names = ['api.ppq.ai'];
  const expectedTxt = dnsTxtValue(keyAuthorization('tok-api.ppq.ai', accountKey));
  const txt = new Map();
  const gd = fakeFetch((method, url) => {
    if (method === 'PUT') txt.set('_acme-challenge.api.ppq.ai', expectedTxt);
    if (method === 'DELETE') txt.delete('_acme-challenge.api.ppq.ai');
    return method === 'DELETE' ? 204 : 200;
  });
  const Resolver = fakeResolverClass({ txt });
  const { client, calls } = fakeClient({ names, outcomes: () => 'valid' });
  const settles = [];
  const logs = [];
  const d = createDns01({
    zone: ZONE, godaddyToken: 'T', log: (m) => logs.push(m), settleSeconds: 7, fetchImpl: gd.fetch, Resolver,
    setTimeout: (fn, ms) => { settles.push(ms); fn(); return 0; },
  });
  const chain = await d.obtainCertificate({ client, accountKey, names, csrDer: Buffer.from('csr') });
  assert.equal(chain, 'CHAIN-PEM');
  assert.deepEqual(gd.calls.map((c) => `${c.method} ${c.url.split('/domains/ppq.ai')[1]}`), [
    'PUT /records/TXT/_acme-challenge.api', 'DELETE /records/TXT/_acme-challenge.api',
  ]);
  assert.deepEqual(gd.calls[0].body, [{ data: expectedTxt, ttl: 600 }]);
  assert.deepEqual(settles, [7000], 'exactly one settle of settleSeconds, no retry wait');
  assert.deepEqual(calls.accepted, ['chal:1:api.ppq.ai']);
  assert.equal(calls.newOrder, 1);
  assert.deepEqual(calls.finalize, { url: 'finalize:1', csr: Buffer.from('csr') });
  assert.equal(calls.downloaded, 'cert:1');
  assert.ok(logs.some((m) => m === `TXT _acme-challenge.api.${ZONE} = ${expectedTxt}`));
  assert.ok(logs.some((m) => m.startsWith('cleaned TXT _acme-challenge.api (204)')));
});

test('obtainCertificate: record names for the apex and a wildcard; a name outside the zone is refused', async () => {
  const accountKey = generateAccountKey().privateKey;
  const rrs = [];
  const txt = new Map();
  const gd = fakeFetch((method, url) => {
    const rr = url.split('/records/TXT/')[1];
    if (method === 'PUT') { rrs.push(rr); txt.set(`${rr}.${ZONE}`, 'any'); }
    return 200;
  });
  // Every nameserver "sees" whatever was placed: resolveTxt returns the value stored for the fqdn.
  class Resolver extends fakeResolverClass({ txt }) {
    async resolveTxt(fqdn) { return txt.has(fqdn) ? [[dnsTxtValue(keyAuthorization(`tok-${this.constructor.nameFor(fqdn)}`, accountKey))]] : []; }
    static nameFor(fqdn) { return this.names.find((n) => fqdn === (n.replace(/^\*\./, '') === ZONE ? `_acme-challenge.${ZONE}` : `_acme-challenge.${n.replace(/^\*\./, '')}`)); }
  }
  Resolver.names = ['ppq.ai', '*.lab.ppq.ai'];
  const { client } = fakeClient({ names: Resolver.names, outcomes: () => 'valid' });
  const d = createDns01({ zone: ZONE, godaddyToken: 'T', log: noop, settleSeconds: 0, fetchImpl: gd.fetch, Resolver, setTimeout: immediate });
  await d.obtainCertificate({ client, accountKey, names: Resolver.names, csrDer: Buffer.alloc(1) });
  assert.deepEqual(rrs, ['_acme-challenge', '_acme-challenge.lab']);

  const bad = fakeClient({ names: ['api.example.com'], outcomes: () => 'valid' });
  await assert.rejects(
    d.obtainCertificate({ client: bad.client, accountKey, names: ['api.example.com'], csrDer: Buffer.alloc(1) }),
    /api\.example\.com is not under ppq\.ai/,
  );
});

test('obtainCertificate: a DNS-class failure gets ONE fresh order with the record left in place, then cleanup', async () => {
  const accountKey = generateAccountKey().privateKey;
  const names = ['api.ppq.ai'];
  const txt = new Map();
  const gd = fakeFetch((method) => {
    if (method === 'PUT') txt.set('_acme-challenge.api.ppq.ai', dnsTxtValue(keyAuthorization('tok-api.ppq.ai', accountKey)));
    return method === 'DELETE' ? 204 : 200;
  });
  const Resolver = fakeResolverClass({ txt });
  const { client, calls } = fakeClient({ names, outcomes: (order) => (order === 1 ? 'urn:ietf:params:acme:error:dns' : 'valid') });
  const waits = [];
  const d = createDns01({ zone: ZONE, godaddyToken: 'T', log: noop, settleSeconds: 0, orderAttempts: 2, fetchImpl: gd.fetch, Resolver, setTimeout: (fn, ms) => { waits.push(ms); fn(); return 0; } });
  assert.equal(await d.obtainCertificate({ client, accountKey, names, csrDer: Buffer.alloc(1) }), 'CHAIN-PEM');
  assert.equal(calls.newOrder, 2);
  assert.deepEqual(waits, [0, 60_000, 0], 'settle, the 60s retry wait, settle again');
  const seq = gd.calls.map((c) => c.method);
  assert.deepEqual(seq, ['PUT', 'PUT', 'DELETE'], 'the record is re-put for the fresh order and deleted once, at the end');
  assert.equal(calls.finalize.url, 'finalize:2');
});

test('obtainCertificate: a second DNS-class failure, or any other failure, throws -- and still cleans up', async () => {
  const accountKey = generateAccountKey().privateKey;
  const names = ['api.ppq.ai'];
  const txt = new Map();
  const mk = (outcomes) => {
    const gd = fakeFetch((method) => {
      if (method === 'PUT') txt.set('_acme-challenge.api.ppq.ai', dnsTxtValue(keyAuthorization('tok-api.ppq.ai', accountKey)));
      return method === 'DELETE' ? 204 : 200;
    });
    const { client, calls } = fakeClient({ names, outcomes });
    const d = createDns01({ zone: ZONE, godaddyToken: 'T', log: noop, settleSeconds: 0, fetchImpl: gd.fetch, Resolver: fakeResolverClass({ txt }), setTimeout: immediate });
    return { gd, client, calls, d };
  };
  const twice = mk(() => 'urn:ietf:params:acme:error:dns');
  await assert.rejects(twice.d.obtainCertificate({ client: twice.client, accountKey, names, csrDer: Buffer.alloc(1) }), /authorization for api\.ppq\.ai invalid: .*error:dns/);
  assert.equal(twice.calls.newOrder, 2);
  assert.equal(twice.gd.calls.filter((c) => c.method === 'DELETE').length, 1);
  assert.equal(twice.calls.finalize, null);

  const other = mk(() => 'urn:ietf:params:acme:error:unauthorized');
  await assert.rejects(other.d.obtainCertificate({ client: other.client, accountKey, names, csrDer: Buffer.alloc(1) }), /error:unauthorized/);
  assert.equal(other.calls.newOrder, 1, 'no retry for a non-DNS failure');
  assert.equal(other.gd.calls.filter((c) => c.method === 'DELETE').length, 1);
});

test('obtainCertificate: the wait requires EVERY nameserver, not just the first', async () => {
  const accountKey = generateAccountKey().privateKey;
  const names = ['api.ppq.ai'];
  const txt = new Map();
  const blind = new Set(['10.0.0.3']); // one anycast address never catches up
  const gd = fakeFetch((method) => { if (method === 'PUT') txt.set('_acme-challenge.api.ppq.ai', dnsTxtValue(keyAuthorization('tok-api.ppq.ai', accountKey))); return 200; });
  const { client, calls } = fakeClient({ names, outcomes: () => 'valid' });
  let polls = 0;
  const d = createDns01({
    zone: ZONE, godaddyToken: 'T', log: noop, settleSeconds: 0, fetchImpl: gd.fetch, Resolver: fakeResolverClass({ txt, blind }),
    setTimeout: (fn, ms) => { if (ms === 5000) { polls += 1; if (polls === 3) blind.clear(); } fn(); return 0; },
  });
  // pollUntil sleeps 5000 between attempts; the blind server "catches up" after three sleeps.
  assert.equal(await d.obtainCertificate({ client, accountKey, names, csrDer: Buffer.alloc(1) }), 'CHAIN-PEM');
  assert.equal(polls, 3);
  assert.equal(calls.accepted.length, 1);
});
