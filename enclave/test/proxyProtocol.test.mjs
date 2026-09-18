import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProxyV2, buildProxyV2, formatIPv6, PROXY_V2_SIGNATURE } from '../src/proxyProtocol.mjs';

test('v2 TCP4: source address and port, exact header length', () => {
  const h = buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445);
  assert.equal(h.length, 28);
  const r = parseProxyV2(h);
  assert.deepEqual(r, { status: 'ok', headerLength: 28, command: 'PROXY', family: 'TCP4', ip: '203.0.113.9', port: 51234 });
});

test('v2 TCP6: RFC 5952 rendering of the source', () => {
  const h = buildProxyV2('2001:db8::1', 443, '2001:db8:0:0:0:0:0:2', 8445);
  assert.equal(h.length, 52);
  const r = parseProxyV2(h);
  assert.equal(r.status, 'ok');
  assert.equal(r.family, 'TCP6');
  assert.equal(r.ip, '2001:db8::1');
  assert.equal(r.port, 443);
  assert.equal(r.headerLength, 52);
});

test('v2 TCP6 with an IPv4-mapped source renders as the v4 literal', () => {
  const h = buildProxyV2('::ffff:198.51.100.7', 7, '::1', 8445);
  const r = parseProxyV2(h);
  assert.equal(r.status, 'ok');
  assert.equal(r.family, 'TCP6');
  assert.equal(r.ip, '198.51.100.7');
});

test('formatIPv6: longest zero run collapses, ties go to the first, single zero does not collapse', () => {
  const b = (groups) => {
    const out = Buffer.alloc(16);
    groups.forEach((g, i) => out.writeUInt16BE(g, i * 2));
    return out;
  };
  assert.equal(formatIPv6(b([0, 0, 0, 0, 0, 0, 0, 1])), '::1');
  assert.equal(formatIPv6(b([0, 0, 0, 0, 0, 0, 0, 0])), '::');
  assert.equal(formatIPv6(b([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1])), '2001:db8::1:0:0:1');
  assert.equal(formatIPv6(b([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1])), '2001:db8:0:1:1:1:1:1');
  assert.equal(formatIPv6(b([0xfe80, 0, 0, 0, 0x1ff, 0xfe23, 0x4567, 0x890a])), 'fe80::1ff:fe23:4567:890a');
});

test('the header bytes are exactly the documented layout', () => {
  const h = buildProxyV2('1.2.3.4', 0x1234, '5.6.7.8', 0x5678);
  assert.ok(h.subarray(0, 12).equals(PROXY_V2_SIGNATURE));
  assert.equal(h[12], 0x21, 'version 2 | PROXY');
  assert.equal(h[13], 0x11, 'INET | STREAM');
  assert.equal(h.readUInt16BE(14), 12);
  assert.deepEqual([...h.subarray(16, 20)], [1, 2, 3, 4]);
  assert.deepEqual([...h.subarray(20, 24)], [5, 6, 7, 8]);
  assert.equal(h.readUInt16BE(24), 0x1234);
  assert.equal(h.readUInt16BE(26), 0x5678);
});

test('LOCAL command: ok, no address', () => {
  const h = buildProxyV2(null, 0, null, 0, { command: 'LOCAL' });
  assert.equal(h.length, 16);
  assert.deepEqual(parseProxyV2(h), { status: 'ok', headerLength: 16, command: 'LOCAL', family: 'UNSPEC' });
  // LOCAL with a non-empty (ignored) address block still reports the full length.
  const withBlock = Buffer.concat([h, Buffer.alloc(12, 0xaa)]);
  withBlock.writeUInt16BE(12, 14);
  assert.deepEqual(parseProxyV2(withBlock), { status: 'ok', headerLength: 28, command: 'LOCAL', family: 'UNSPEC' });
});

test('TLVs after the addresses are skipped by the length field', () => {
  const tlvs = Buffer.from([0x01, 0x00, 0x05, 0x68, 0x32, 0x2c, 0x68, 0x31, 0x20, 0x00, 0x01, 0x07]);
  const h = buildProxyV2('203.0.113.9', 1, '10.0.0.5', 2, { tlvs });
  assert.equal(h.length, 28 + tlvs.length);
  const r = parseProxyV2(Buffer.concat([h, Buffer.from('CLIENTHELLO')]));
  assert.equal(r.status, 'ok');
  assert.equal(r.headerLength, 28 + tlvs.length, 'header length excludes trailing bytes and includes TLVs');
  assert.equal(r.ip, '203.0.113.9');
});

test('a v1 text header is invalid, from the first byte', () => {
  assert.equal(parseProxyV2(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n')).status, 'invalid');
  assert.equal(parseProxyV2(Buffer.from('P')).status, 'invalid');
});

test('a bare TLS ClientHello (no header) is invalid, from the first byte', () => {
  assert.equal(parseProxyV2(Buffer.from([0x16, 0x03, 0x01, 0x00, 0xf8])).status, 'invalid');
});

test('bad signature, bad version, bad command, unsupported family are invalid', () => {
  const good = buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2);
  const mutate = (i, v) => {
    const c = Buffer.from(good);
    c[i] = v;
    return c;
  };
  assert.equal(parseProxyV2(mutate(11, 0x00)).status, 'invalid', 'signature');
  assert.equal(parseProxyV2(mutate(12, 0x11)).status, 'invalid', 'version 1 nibble');
  assert.equal(parseProxyV2(mutate(12, 0x22)).status, 'invalid', 'command 2');
  assert.equal(parseProxyV2(mutate(13, 0x12)).status, 'invalid', 'UDP4');
  assert.equal(parseProxyV2(mutate(13, 0x31)).status, 'invalid', 'unix stream');
  // Declared family needs more address bytes than the length field carries.
  const short = Buffer.from(good);
  short[13] = 0x21;
  assert.equal(parseProxyV2(short).status, 'invalid', 'TCP6 with a 12-byte block');
});

test('UNSPEC family with PROXY command: ok, no address (spec says ignore)', () => {
  const h = buildProxyV2('1.2.3.4', 1, '5.6.7.8', 2);
  h[13] = 0x00;
  assert.deepEqual(parseProxyV2(h), { status: 'ok', headerLength: 28, command: 'PROXY', family: 'UNSPEC' });
});

test('truncated input is incomplete with the exact byte count needed', () => {
  const h = buildProxyV2('203.0.113.9', 51234, '10.0.0.5', 8445);
  assert.deepEqual(parseProxyV2(Buffer.alloc(0)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 5)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 15)), { status: 'incomplete', need: 16 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 16)), { status: 'incomplete', need: 28 });
  assert.deepEqual(parseProxyV2(h.subarray(0, 27)), { status: 'incomplete', need: 28 });
  assert.equal(parseProxyV2(h.subarray(0, 28)).status, 'ok');
});

test('never throws: garbage of every kind is invalid', () => {
  for (const input of [undefined, null, 'string', 42, {}, [], Buffer.alloc(100, 0xff), Buffer.alloc(16, 0)]) {
    assert.equal(parseProxyV2(input).status, 'invalid');
  }
});
