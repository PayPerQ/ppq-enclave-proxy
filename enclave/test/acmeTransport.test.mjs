// The transport's job is to reach a pinned host through a loopback tunnel while
// validating TLS against the REAL name. The name is the security property: it
// is what stops the parent pointing a tunnel somewhere else and being believed.

import assert from 'node:assert/strict';
import test from 'node:test';
import { createAcmeFetch } from '../src/acmeTransport.mjs';

test('refuses a host with no tunnel rather than leaking to the default route', async () => {
  // The enclave has no NIC, so an untunnelled request cannot succeed anyway --
  // but failing loudly names the missing tunnel instead of timing out.
  const f = createAcmeFetch({ 'acme-staging-v02.api.letsencrypt.org': 9451 });
  await assert.rejects(
    () => f('https://evil.example/directory'),
    /no vsock tunnel for evil\.example/,
  );
});

test('names the tunnels it does have, so a typo is obvious', async () => {
  const f = createAcmeFetch({ 'acme-staging-v02.api.letsencrypt.org': 9451 });
  await assert.rejects(() => f('https://acme-v02.api.letsencrypt.org/x'), /acme-staging-v02/);
});

test('an empty tunnel map fails clearly', async () => {
  const f = createAcmeFetch({});
  await assert.rejects(() => f('https://acme-v02.api.letsencrypt.org/x'), /have: none/);
});

test('a zero port counts as no tunnel', async () => {
  // boot.sh exports 0 when the port is unset, and connecting to :0 would be a
  // confusing failure far from the cause.
  const f = createAcmeFetch({ 'acme-v02.api.letsencrypt.org': 0 });
  await assert.rejects(() => f('https://acme-v02.api.letsencrypt.org/x'), /no vsock tunnel/);
});
