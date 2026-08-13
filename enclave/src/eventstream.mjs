/**
 * AWS `application/vnd.amazon.eventstream` binary framing — parser (+ an
 * encoder used only by tests). Dependency-free: node:zlib's crc32 (Node ≥
 * 20.15; the pinned node:22 image has it).
 *
 * Wire format, per message:
 *   [u32 BE total length][u32 BE headers length][u32 BE prelude CRC32]
 *   [headers bytes][payload bytes][u32 BE message CRC32]
 * - prelude CRC covers the first 8 bytes (both lengths);
 * - message CRC covers everything before it (prelude incl. its CRC + headers
 *   + payload).
 * Each header: [u8 name length][name][u8 value type][value]. Bedrock uses only
 * type 7 (string: [u16 BE length][utf8 bytes]) for its `:message-type`,
 * `:event-type`, `:exception-type`, `:content-type` headers; other types are
 * skipped structurally (length known) but not decoded.
 *
 * Posture on corruption: a CRC or structural failure THROWS. The caller
 * terminates the stream — a half-trusted frame must never be billed or
 * forwarded, and the fallback story (client sees a terminated stream, exactly
 * like an OpenRouter mid-stream death) is acceptable.
 */
import zlib from 'node:zlib';

if (typeof zlib.crc32 !== 'function') {
  // Fail at import, loudly — the image's Node is pinned, so this can only
  // happen on a wrong local runtime.
  throw new Error('node:zlib crc32 is required (Node >= 20.15)');
}
const crc32 = (buf) => zlib.crc32(buf) >>> 0;

// Header value types (only STRING is decoded; the rest sized-skip).
const TYPE_BOOL_TRUE = 0;
const TYPE_BOOL_FALSE = 1;
const TYPE_BYTE = 2;
const TYPE_SHORT = 3;
const TYPE_INT = 4;
const TYPE_LONG = 5;
const TYPE_BYTE_ARRAY = 6;
const TYPE_STRING = 7;
const TYPE_TIMESTAMP = 8;
const TYPE_UUID = 9;

function parseHeaders(buf) {
  const headers = {};
  let off = 0;
  while (off < buf.length) {
    const nameLen = buf.readUInt8(off);
    off += 1;
    const name = buf.toString('utf8', off, off + nameLen);
    off += nameLen;
    const type = buf.readUInt8(off);
    off += 1;
    switch (type) {
      case TYPE_BOOL_TRUE:
        headers[name] = true;
        break;
      case TYPE_BOOL_FALSE:
        headers[name] = false;
        break;
      case TYPE_BYTE:
        off += 1;
        break;
      case TYPE_SHORT:
        off += 2;
        break;
      case TYPE_INT:
        off += 4;
        break;
      case TYPE_LONG:
      case TYPE_TIMESTAMP:
        off += 8;
        break;
      case TYPE_BYTE_ARRAY: {
        const len = buf.readUInt16BE(off);
        off += 2 + len;
        break;
      }
      case TYPE_STRING: {
        const len = buf.readUInt16BE(off);
        off += 2;
        headers[name] = buf.toString('utf8', off, off + len);
        off += len;
        break;
      }
      case TYPE_UUID:
        off += 16;
        break;
      default:
        throw new Error(`eventstream: unknown header value type ${type}`);
    }
  }
  if (off !== buf.length) throw new Error('eventstream: malformed headers block');
  return headers;
}

// Prelude is 12 bytes; the two CRCs and both lengths bound a frame to sane
// sizes. 16 MB caps a single frame well above any real Converse event while
// keeping a corrupted length field from buffering unbounded memory.
const PRELUDE_LEN = 12;
const MAX_FRAME_LEN = 16 * 1024 * 1024;

/**
 * Incremental parser: feed() raw TCP chunks in any fragmentation, get back
 * complete messages `{headers, payload}` in order. Throws on corruption.
 */
export class EventStreamParser {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  /** @returns {Array<{headers: Record<string, any>, payload: Buffer}>} */
  feed(chunk) {
    this.buffer = this.buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    const messages = [];
    for (;;) {
      if (this.buffer.length < PRELUDE_LEN) break;
      const totalLen = this.buffer.readUInt32BE(0);
      if (totalLen < PRELUDE_LEN + 4 || totalLen > MAX_FRAME_LEN) {
        throw new Error(`eventstream: implausible frame length ${totalLen}`);
      }
      const headersLen = this.buffer.readUInt32BE(4);
      const preludeCrc = this.buffer.readUInt32BE(8);
      if (crc32(this.buffer.subarray(0, 8)) !== preludeCrc) {
        throw new Error('eventstream: prelude CRC mismatch');
      }
      if (headersLen > totalLen - PRELUDE_LEN - 4) {
        throw new Error('eventstream: headers length exceeds frame');
      }
      if (this.buffer.length < totalLen) break; // wait for the rest

      const frame = this.buffer.subarray(0, totalLen);
      const messageCrc = frame.readUInt32BE(totalLen - 4);
      if (crc32(frame.subarray(0, totalLen - 4)) !== messageCrc) {
        throw new Error('eventstream: message CRC mismatch');
      }
      const headers = parseHeaders(frame.subarray(PRELUDE_LEN, PRELUDE_LEN + headersLen));
      // subarray views the shared buffer; copy so a later concat can't alias.
      const payload = Buffer.from(
        frame.subarray(PRELUDE_LEN + headersLen, totalLen - 4),
      );
      messages.push({ headers, payload });
      this.buffer = this.buffer.subarray(totalLen);
    }
    return messages;
  }

  /** True when a partial frame is still buffered (truncated stream). */
  hasPartial() {
    return this.buffer.length > 0;
  }
}

/**
 * TEST-ONLY encoder (string headers): builds a spec-shaped frame so parser
 * tests can synthesize streams. The wire-format truth is still pinned by a
 * hand-built byte fixture in the tests, not by this encoder alone.
 */
export function encodeEventStreamMessage({ headers = {}, payload = Buffer.alloc(0) }) {
  const headerParts = [];
  for (const [name, value] of Object.entries(headers)) {
    const nameBuf = Buffer.from(name, 'utf8');
    const valueBuf = Buffer.from(String(value), 'utf8');
    const part = Buffer.alloc(1 + nameBuf.length + 1 + 2 + valueBuf.length);
    let off = 0;
    part.writeUInt8(nameBuf.length, off); off += 1;
    nameBuf.copy(part, off); off += nameBuf.length;
    part.writeUInt8(TYPE_STRING, off); off += 1;
    part.writeUInt16BE(valueBuf.length, off); off += 2;
    valueBuf.copy(part, off);
    headerParts.push(part);
  }
  const headersBuf = Buffer.concat(headerParts);
  const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const totalLen = PRELUDE_LEN + headersBuf.length + payloadBuf.length + 4;

  const frame = Buffer.alloc(totalLen);
  frame.writeUInt32BE(totalLen, 0);
  frame.writeUInt32BE(headersBuf.length, 4);
  frame.writeUInt32BE(crc32(frame.subarray(0, 8)), 8);
  headersBuf.copy(frame, PRELUDE_LEN);
  payloadBuf.copy(frame, PRELUDE_LEN + headersBuf.length);
  frame.writeUInt32BE(crc32(frame.subarray(0, totalLen - 4)), totalLen - 4);
  return frame;
}
