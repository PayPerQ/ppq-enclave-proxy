import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authorizeHeaders, AUTHORIZE_FORWARDED_HEADERS } from '../src/authorizeHeaders.mjs';
import { enclaveClientIpMac } from '../src/passthrough.mjs';

const base = { host: 'hp.example', bodyLength: 42 };
// 2026-09-17T12:00:30Z → unix minute 29827800
const NOW = 29_827_800 * 60_000 + 30_000;

test('carries the credential/intent allow-list and the fixed envelope', () => {
  const h = authorizeHeaders(
    {
      authorization: 'Bearer sk-1',
      'x-api-key': 'sk-2',
      'x-credit-id': 'c-3',
      'x-query-source': 'web',
      'x-ppq-intent': 'title',
      'user-agent': 'not forwarded',
      cookie: 'not forwarded',
    },
    base,
  );
  assert.deepEqual(h, {
    'content-type': 'application/json',
    'content-length': 42,
    host: 'hp.example',
    authorization: 'Bearer sk-1',
    'x-api-key': 'sk-2',
    'x-credit-id': 'c-3',
    'x-query-source': 'web',
    'x-ppq-intent': 'title',
  });
  assert.deepEqual([...AUTHORIZE_FORWARDED_HEADERS], ['authorization', 'x-api-key', 'x-credit-id', 'x-query-source', 'x-ppq-intent']);
});

test('adds the MAC pair only when BOTH the socket address and the secret are present', () => {
  const withBoth = authorizeHeaders({}, { ...base, clientIp: '203.0.113.9', secret: 's3cret', now: NOW });
  assert.equal(withBoth['x-ppq-client-ip'], '203.0.113.9');
  assert.equal(withBoth['x-ppq-client-ip-mac'], enclaveClientIpMac('203.0.113.9', 29_827_800, 's3cret'));

  const noSecret = authorizeHeaders({}, { ...base, clientIp: '203.0.113.9', secret: '', now: NOW });
  assert.equal(noSecret['x-ppq-client-ip'], undefined);
  assert.equal(noSecret['x-ppq-client-ip-mac'], undefined);

  const noIp = authorizeHeaders({}, { ...base, clientIp: undefined, secret: 's3cret', now: NOW });
  assert.equal(noIp['x-ppq-client-ip'], undefined);
  assert.equal(noIp['x-ppq-client-ip-mac'], undefined);

  const v6 = authorizeHeaders({}, { ...base, clientIp: '2001:db8::1', secret: 's3cret', now: NOW });
  assert.equal(v6['x-ppq-client-ip'], '2001:db8::1');
  assert.equal(v6['x-ppq-client-ip-mac'], enclaveClientIpMac('2001:db8::1', 29_827_800, 's3cret'));
});

test('the MAC is over the current unix minute, so it rolls with the clock (hp accepts current or previous)', () => {
  const a = authorizeHeaders({}, { ...base, clientIp: '1.2.3.4', secret: 'k', now: NOW });
  const b = authorizeHeaders({}, { ...base, clientIp: '1.2.3.4', secret: 'k', now: NOW + 60_000 });
  assert.notEqual(a['x-ppq-client-ip-mac'], b['x-ppq-client-ip-mac']);
  assert.equal(a['x-ppq-client-ip-mac'], enclaveClientIpMac('1.2.3.4', Math.floor(NOW / 60_000), 'k'));
});

test('a client-supplied x-ppq-client-ip pair never reaches hp, with or without a socket address', () => {
  const forged = { 'x-ppq-client-ip': '9.9.9.9', 'x-ppq-client-ip-mac': 'deadbeef', 'x-forwarded-for': '9.9.9.9', 'x-real-ip': '9.9.9.9' };
  const without = authorizeHeaders(forged, { ...base, secret: 's3cret', now: NOW });
  assert.equal(without['x-ppq-client-ip'], undefined);
  assert.equal(without['x-ppq-client-ip-mac'], undefined);
  assert.equal(without['x-forwarded-for'], undefined);
  assert.equal(without['x-real-ip'], undefined);

  const withSocket = authorizeHeaders(forged, { ...base, clientIp: '203.0.113.9', secret: 's3cret', now: NOW });
  assert.equal(withSocket['x-ppq-client-ip'], '203.0.113.9');
  assert.equal(withSocket['x-ppq-client-ip-mac'], enclaveClientIpMac('203.0.113.9', 29_827_800, 's3cret'));
});

test('non-string or empty header values are not forwarded', () => {
  const h = authorizeHeaders({ authorization: ['a', 'b'], 'x-credit-id': '', 'x-api-key': 7 }, base);
  assert.equal(h.authorization, undefined);
  assert.equal(h['x-credit-id'], undefined);
  assert.equal(h['x-api-key'], undefined);
  // And a missing headers object is tolerated.
  assert.equal(authorizeHeaders(undefined, base).host, 'hp.example');
});

test('sets x-request-id from the explicit id the enclave resolved', () => {
  const h = authorizeHeaders({}, { ...base, requestId: 'enc-1759000000000-abc123' });
  assert.equal(h['x-request-id'], 'enc-1759000000000-abc123');
  const client = authorizeHeaders({}, { ...base, requestId: 'req-client.1_2' });
  assert.equal(client['x-request-id'], 'req-client.1_2');
});

test('sends no x-request-id when no id is given, even if the client sent one', () => {
  assert.equal('x-request-id' in authorizeHeaders({}, base), false);
  assert.equal('x-request-id' in authorizeHeaders({ 'x-request-id': 'from-client' }, base), false);
  assert.equal('x-request-id' in authorizeHeaders({}, { ...base, requestId: '' }), false);
});

test('the explicit id wins over a different client-supplied x-request-id', () => {
  const h = authorizeHeaders({ 'x-request-id': 'from-client' }, { ...base, requestId: 'enc-1759000000000-zz' });
  assert.equal(h['x-request-id'], 'enc-1759000000000-zz');
});

test('an id outside the accepted correlation-id shape is left out, never truncated', () => {
  for (const bad of ['a'.repeat(65), 'has space', 'semi;colon', 'line\nbreak', '../x/y', 42, null]) {
    assert.equal('x-request-id' in authorizeHeaders({}, { ...base, requestId: bad }), false, String(bad));
  }
  assert.equal(authorizeHeaders({}, { ...base, requestId: 'a'.repeat(64) })['x-request-id'], 'a'.repeat(64));
});
