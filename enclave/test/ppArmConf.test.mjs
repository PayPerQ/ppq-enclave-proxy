// The api arm exists in two files: scripts/nginx-pp-arm.conf (its own
// stream {}, for a box with no stream context) and
// scripts/nginx-pp-arm-server.conf (the server block alone, included inside
// production's existing stream block by scripts/install-pp-arm.sh). They must
// describe the same listener, or the dev rehearsal stops being a rehearsal of
// production.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (f) => readFileSync(join(root, 'scripts', f), 'utf8');
const serverBlock = (text) => {
  const m = text.match(/^\s*server\s*\{[\s\S]*?^\s*\}/m);
  assert.ok(m, 'no server block');
  return m[0].split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).join('\n');
};

test('nginx-pp-arm-server.conf is the same server block as nginx-pp-arm.conf', () => {
  assert.equal(serverBlock(read('nginx-pp-arm-server.conf')), serverBlock(read('nginx-pp-arm.conf')));
});

test('the arm listens on 8445 with proxy_protocol on and no inbound header parsing', () => {
  const block = serverBlock(read('nginx-pp-arm-server.conf'));
  assert.match(block, /^listen 8445;$/m, 'must listen on 8445 WITHOUT `proxy_protocol` on the listen line');
  assert.match(block, /^proxy_protocol on;$/m);
  assert.match(block, /^proxy_pass unix:\/run\/ppq\/pp\.sock;$/m);
  assert.match(block, /^ssl_preread on;$/m);
});

test('nginx-sni-split.conf (the production record) carries the same arm', () => {
  const prod = read('nginx-sni-split.conf');
  const arm = serverBlock(read('nginx-pp-arm-server.conf'));
  const blocks = [...prod.matchAll(/^\s*server\s*\{[\s\S]*?^\s*\}/gm)].map((m) => m[0].split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).join('\n'));
  assert.ok(blocks.includes(arm), 'nginx-sni-split.conf must contain the arm server block verbatim');
});
