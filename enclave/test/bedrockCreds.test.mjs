import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BedrockCredsHolder } from '../src/bedrockCreds.mjs';

const FUTURE = new Date(Date.now() + 3600_000).toISOString();

function plaintextBlob(overrides = {}) {
  return {
    bedrock_access_key_id: 'AKIDEXAMPLE',
    bedrock_secret_access_key: 'secret',
    bedrock_session_token: 'token',
    bedrock_expiration: FUTURE,
    ...overrides,
  };
}

test('plaintext blob with a future ISO expiration installs and get() serves it', async () => {
  const holder = new BedrockCredsHolder({ log: () => {} });
  assert.equal(await holder.applyBlob(plaintextBlob()), true);
  const creds = holder.get();
  assert.equal(creds.accessKeyId, 'AKIDEXAMPLE');
  assert.equal(creds.sessionToken, 'token');
  assert.ok(creds.expiration instanceof Date);
});

test('creds WITHOUT a parsable expiration are rejected, not treated as eternal', async () => {
  // These are short-lived STS creds by design; "no expiration" must not
  // degrade into signing with dead credentials forever (CodeRabbit, PR #17).
  const holder = new BedrockCredsHolder({ log: () => {} });
  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: undefined })), false);
  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: '' })), false);
  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: 'not-a-date' })), false);
  assert.equal(holder.get(), null);
});

test('epoch expirations (seconds and millis, number or string) are accepted', async () => {
  const holder = new BedrockCredsHolder({ log: () => {} });
  const epochSeconds = Math.floor((Date.now() + 3600_000) / 1000);

  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: epochSeconds })), true);
  assert.equal(holder.get().expiration.getTime(), epochSeconds * 1000);

  assert.equal(
    await holder.applyBlob(plaintextBlob({ bedrock_expiration: String(epochSeconds) })),
    true,
  );
  assert.equal(holder.get().expiration.getTime(), epochSeconds * 1000);

  const epochMillis = Date.now() + 3600_000;
  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: epochMillis })), true);
  assert.equal(holder.get().expiration.getTime(), epochMillis);
});

test('get() returns null inside the 60s pre-expiry margin; a fresh blob replaces atomically', async () => {
  const holder = new BedrockCredsHolder({ log: () => {} });
  const soon = new Date(Date.now() + 30_000).toISOString();
  assert.equal(await holder.applyBlob(plaintextBlob({ bedrock_expiration: soon })), true);
  assert.equal(holder.get(), null); // within the margin — skip, don't sign

  assert.equal(await holder.applyBlob(plaintextBlob()), true);
  assert.ok(holder.get());
});

test('a malformed blob never clobbers previously installed creds', async () => {
  const holder = new BedrockCredsHolder({ log: () => {} });
  assert.equal(await holder.applyBlob(plaintextBlob()), true);
  assert.equal(await holder.applyBlob({ bedrock_access_key_id: 42 }), false);
  assert.ok(holder.get(), 'previous creds survive a bad refresh');
});

// ── #52 scaling: the primary forwards host pushes instead of applying them ───
import net from 'node:net';
import { BedrockCredsHolder as HolderForFanout } from '../src/bedrockCreds.mjs';

test('onBlob: a pushed blob is handed to the hook and NOT applied locally', async () => {
  const holder = new HolderForFanout({ log: () => {} });
  const seen = [];
  holder.onBlob = (blob) => seen.push(blob);
  const server = holder.listen(0);
  await new Promise((r) => server.once('listening', r));
  const { port } = server.address();
  await new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.end(JSON.stringify({ bedrock_access_key_id: 'AKIA', bedrock_secret_access_key: 's', bedrock_session_token: 't' }));
    });
    sock.on('close', resolve);
    sock.on('error', reject);
  });
  await new Promise((r) => setTimeout(r, 50));
  server.close();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].bedrock_access_key_id, 'AKIA');
  assert.equal(holder.get(), null, 'the primary does not serve, so it must not install creds');
});
