// Every outbound tunnel needs its own vsock port on both ends. Two upstreams
// added on parallel branches (Venice #215, Tinfoil #210) both took 9454 and git
// merged it without a conflict; the host would start one proxy per line and the
// enclave would reach whichever bound first.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (f) => readFileSync(join(root, f), 'utf8');

const dupes = (xs) => xs.filter((x, i) => xs.indexOf(x) !== i);

test('run-host.sh starts at most one vsock-proxy per port', () => {
  const ports = [...read('scripts/run-host.sh').matchAll(/^\s+"(\d{4,5}) \S+ \$\{\w+\}"/gm)].map((m) => m[1]);
  assert.ok(ports.length >= 10, `parsed only ${ports.length} tunnels`);
  assert.deepEqual(dupes(ports), []);
});

test('boot.sh gives every *_VSOCK_PORT a distinct value', () => {
  const entries = [...read('enclave/boot.sh').matchAll(/^(\w+_VSOCK_PORT)=(\d+)$/gm)].map((m) => [m[1], m[2]]);
  assert.ok(entries.length >= 10, `parsed only ${entries.length} ports`);
  const byPort = {};
  for (const [name, port] of entries) (byPort[port] ??= []).push(name);
  const clashes = Object.entries(byPort).filter(([, names]) => names.length > 1);
  assert.deepEqual(clashes, []);
});
