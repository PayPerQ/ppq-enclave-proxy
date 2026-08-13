import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { EventStreamParser, encodeEventStreamMessage } from '../src/eventstream.mjs';

const crc32 = (buf) => zlib.crc32(buf) >>> 0;

/**
 * Build a frame BY HAND (independent of the encoder) so the wire format —
 * offsets, lengths, CRC coverage — is pinned by explicit bytes, not by the
 * encoder's own opinion of itself.
 */
function handBuiltFrame() {
  const name = Buffer.from(':event-type', 'utf8'); // 11 bytes
  const value = Buffer.from('messageStart', 'utf8'); // 12 bytes
  const headers = Buffer.concat([
    Buffer.from([name.length]),
    name,
    Buffer.from([7]), // value type 7 = string
    Buffer.from([0, value.length]), // u16 BE value length
    value,
  ]); // 1 + 11 + 1 + 2 + 12 = 27 bytes
  const payload = Buffer.from('{"role":"assistant"}', 'utf8'); // 20 bytes
  const totalLen = 12 + headers.length + payload.length + 4; // 63

  const frame = Buffer.alloc(totalLen);
  frame.writeUInt32BE(totalLen, 0);
  frame.writeUInt32BE(headers.length, 4);
  frame.writeUInt32BE(crc32(frame.subarray(0, 8)), 8);
  headers.copy(frame, 12);
  payload.copy(frame, 12 + headers.length);
  frame.writeUInt32BE(crc32(frame.subarray(0, totalLen - 4)), totalLen - 4);
  return frame;
}

test('parses a hand-built frame (wire format pinned by explicit bytes)', () => {
  const parser = new EventStreamParser();
  const messages = parser.feed(handBuiltFrame());
  assert.equal(messages.length, 1);
  assert.deepEqual(messages[0].headers, { ':event-type': 'messageStart' });
  assert.equal(messages[0].payload.toString('utf8'), '{"role":"assistant"}');
  assert.equal(parser.hasPartial(), false);
});

test('encoder round-trips through the parser', () => {
  const frame = encodeEventStreamMessage({
    headers: { ':message-type': 'event', ':event-type': 'contentBlockDelta' },
    payload: Buffer.from('{"delta":{"text":"hello"}}', 'utf8'),
  });
  // Cross-check: the encoder agrees with the hand-built construction.
  const hand = handBuiltFrame();
  const encoded = encodeEventStreamMessage({
    headers: { ':event-type': 'messageStart' },
    payload: Buffer.from('{"role":"assistant"}', 'utf8'),
  });
  assert.deepEqual(encoded, hand);

  const messages = new EventStreamParser().feed(frame);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].headers[':event-type'], 'contentBlockDelta');
});

test('reassembles frames split across arbitrary chunk boundaries', () => {
  const frames = Buffer.concat([
    encodeEventStreamMessage({
      headers: { ':message-type': 'event', ':event-type': 'messageStart' },
      payload: Buffer.from('{"role":"assistant"}'),
    }),
    encodeEventStreamMessage({
      headers: { ':message-type': 'event', ':event-type': 'contentBlockDelta' },
      payload: Buffer.from('{"delta":{"text":"chunky"}}'),
    }),
    encodeEventStreamMessage({
      headers: { ':message-type': 'event', ':event-type': 'messageStop' },
      payload: Buffer.from('{"stopReason":"end_turn"}'),
    }),
  ]);

  // Worst case: one byte at a time.
  const parser = new EventStreamParser();
  const out = [];
  for (const byte of frames) out.push(...parser.feed(Buffer.from([byte])));
  assert.deepEqual(
    out.map((m) => m.headers[':event-type']),
    ['messageStart', 'contentBlockDelta', 'messageStop'],
  );
  assert.equal(parser.hasPartial(), false);

  // And a ragged 7-byte stride for good measure.
  const parser2 = new EventStreamParser();
  const out2 = [];
  for (let i = 0; i < frames.length; i += 7) {
    out2.push(...parser2.feed(frames.subarray(i, i + 7)));
  }
  assert.equal(out2.length, 3);
});

test('corrupted payload byte fails the message CRC', () => {
  const frame = encodeEventStreamMessage({
    headers: { ':event-type': 'messageStart' },
    payload: Buffer.from('{"role":"assistant"}'),
  });
  frame[frame.length - 6] ^= 0xff; // flip a payload byte, CRCs untouched
  assert.throws(() => new EventStreamParser().feed(frame), /message CRC mismatch/);
});

test('corrupted length field fails the prelude CRC', () => {
  const frame = encodeEventStreamMessage({
    headers: { ':event-type': 'messageStart' },
    payload: Buffer.from('{}'),
  });
  frame[6] ^= 0x01; // tamper with headers-length inside the prelude
  assert.throws(() => new EventStreamParser().feed(frame), /prelude CRC mismatch/);
});

test('implausible frame length is rejected before buffering unbounded memory', () => {
  const frame = Buffer.alloc(12);
  frame.writeUInt32BE(0xffffffff, 0);
  frame.writeUInt32BE(0, 4);
  frame.writeUInt32BE(crc32(frame.subarray(0, 8)), 8);
  assert.throws(() => new EventStreamParser().feed(frame), /implausible frame length/);
});

test('hasPartial reports a truncated trailing frame', () => {
  const frame = encodeEventStreamMessage({
    headers: { ':event-type': 'messageStop' },
    payload: Buffer.from('{"stopReason":"end_turn"}'),
  });
  const parser = new EventStreamParser();
  const messages = parser.feed(frame.subarray(0, frame.length - 3));
  assert.equal(messages.length, 0);
  assert.equal(parser.hasPartial(), true);
});

test('skips non-string header types structurally without decoding them', () => {
  // timestamp (type 8, 8 bytes) then a string header — parser must land on it.
  const name1 = Buffer.from(':timestamp');
  const tsHeader = Buffer.concat([
    Buffer.from([name1.length]),
    name1,
    Buffer.from([8]),
    Buffer.alloc(8, 0x11),
  ]);
  const name2 = Buffer.from(':event-type');
  const value2 = Buffer.from('metadata');
  const strHeader = Buffer.concat([
    Buffer.from([name2.length]),
    name2,
    Buffer.from([7]),
    Buffer.from([0, value2.length]),
    value2,
  ]);
  const headers = Buffer.concat([tsHeader, strHeader]);
  const payload = Buffer.from('{"usage":{}}');
  const totalLen = 12 + headers.length + payload.length + 4;
  const frame = Buffer.alloc(totalLen);
  frame.writeUInt32BE(totalLen, 0);
  frame.writeUInt32BE(headers.length, 4);
  frame.writeUInt32BE(crc32(frame.subarray(0, 8)), 8);
  headers.copy(frame, 12);
  payload.copy(frame, 12 + headers.length);
  frame.writeUInt32BE(crc32(frame.subarray(0, totalLen - 4)), totalLen - 4);

  const messages = new EventStreamParser().feed(frame);
  assert.equal(messages[0].headers[':event-type'], 'metadata');
});
