// The pure half of /v1/audio/speech (speech.mjs, #397): the validator never
// echoes a value, the authorize measure is counts and ids only, the chunker
// and the Voxtral text form match horse-power's, the PCM→MP3 transform emits
// frames as PCM arrives, and the request builders speak each provider's wire.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import {
  DEFAULT_CHAR_LIMIT,
  MAX_TTS_INPUT_CHARS,
  SPEECH_API_STYLE,
  SPEECH_ENDPOINT,
  VOXTRAL_LEVELER_PRESET,
  VOXTRAL_SAMPLE_RATE,
  VOXTRAL_UPSTREAM_MODEL,
  buildSpeechUpstreamRequest,
  chunkTtsInput,
  chunksFor,
  createPcmToMp3Transform,
  measureSpeechInput,
  prepareVoxtralInput,
  speechCandidate,
  speechErrorBody,
  validateSpeechRequest,
} from '../src/speech.mjs';
import { EhbpRecipient } from '../src/ehbp-server.mjs';

const PRIVATE_TEXT = 'The quick brown fox jumps over the lazy dog.';

// ── validator ──────────────────────────────────────────────────────────────

test('validateSpeechRequest: accepts the route body and never echoes a value', () => {
  const ok = validateSpeechRequest({ model: ' tinfoil-voxtral-tts ', input: PRIVATE_TEXT, voice: 'de_male', language: 'de', speed: 1.1, tool_id: 'voice:de_male' });
  assert.deepEqual(ok, {
    kind: 'ok',
    value: { model: 'tinfoil-voxtral-tts', input: PRIVATE_TEXT, voice: 'de_male', language: 'de', speed: 1.1, tool_id: 'voice:de_male' },
  });
  assert.equal(validateSpeechRequest({ model: 'm', input: 'x', language_code: 'pt' }).value.language, 'pt', 'the direct handler alias');
  for (const bad of [
    null,
    [],
    { input: PRIVATE_TEXT },
    { model: 'm' },
    { model: 'm', input: '   ' },
    { model: 'm', input: 'x'.repeat(MAX_TTS_INPUT_CHARS + 1) },
    { model: 'm', input: 'x', voice: 'has space' },
    { model: 'm', input: 'x', voice: { $ne: 1 } },
    { model: 'm', input: 'x', language: ['en'] },
    { model: 'm', input: 'x', speed: '1.2' },
    { model: 'm', input: 'x', speed: -1 },
    { model: 'm', input: 'x', tool_id: 'has space' },
  ]) {
    const r = validateSpeechRequest(bad);
    assert.equal(r.kind, 'invalid', JSON.stringify(bad));
    assert.doesNotMatch(r.error.message, /quick brown|has space/, 'no value in the message');
  }
  assert.equal(validateSpeechRequest({ model: 'm', input: 'x'.repeat(MAX_TTS_INPUT_CHARS) }).kind, 'ok');
});

test('measureSpeechInput: counts and the resolution inputs, never the text', () => {
  const m = measureSpeechInput({ model: 'm', input: 'héllo wörld', voice: 'v1', language: 'de', speed: 0.9 });
  assert.deepEqual(m, { endpoint: SPEECH_ENDPOINT, input_bytes: 13, input_chars: 11, voice: 'v1', language: 'de', speed: 0.9 });
  assert.deepEqual(measureSpeechInput({ model: 'm', input: 'abc' }), { endpoint: 'speech', input_bytes: 3, input_chars: 3 });
  assert.equal(JSON.stringify(m).includes('héllo'), false);
});

// ── the candidate ──────────────────────────────────────────────────────────

test('speechCandidate: exactly one well-formed speech candidate, else null', () => {
  const dg = { provider: 'deepgram', api_style: 'speech', host: 'api.deepgram.com', path: '/v1/speak', key_ref: 'deepgram', upstream_model: 'aura-2-thalia-en', voice: 'aura-2-thalia-en', char_limit: 2000 };
  const { path: _hpPath, ...bound } = dg;
  assert.deepEqual(speechCandidate([dg]), { ...bound, language: undefined, speed: undefined }, "hp's path is not read: the provider paths are constants");
  assert.equal(speechCandidate([dg, { provider: 'openrouter' }]), null, 'no terminal: a TTS model has one provider');
  assert.equal(speechCandidate([]), null);
  assert.equal(speechCandidate(undefined), null);
  assert.equal(speechCandidate([{ ...dg, api_style: 'openai' }]), null, 'a chat candidate is not a speech route');
  assert.equal(speechCandidate([{ ...dg, provider: 'openrouter' }]), null);
  assert.equal(speechCandidate([{ ...dg, voice: undefined }]), null, 'hp resolves the voice; the enclave never picks one');
  assert.equal(speechCandidate([{ ...dg, voice: 'a b' }]), null);
  // An older hp without char_limit: the provider default.
  assert.equal(speechCandidate([{ ...dg, char_limit: undefined }]).char_limit, DEFAULT_CHAR_LIMIT.deepgram);
  assert.equal(speechCandidate([{ ...dg, provider: 'tinfoil', host: 'inference.tinfoil.sh', key_ref: 'tinfoil', char_limit: 0 }]).char_limit, 1200);
  assert.equal(SPEECH_API_STYLE, 'speech');
});

// ── text ───────────────────────────────────────────────────────────────────

test('chunkTtsInput: natural boundaries first, then a hard cut; whitespace-only pieces dropped', () => {
  assert.deepEqual(chunkTtsInput('  short  ', 100), ['short']);
  assert.deepEqual(chunkTtsInput('   ', 100), []);
  const two = chunkTtsInput('First sentence here. Second sentence here.', 25);
  assert.deepEqual(two, ['First sentence here.', 'Second sentence here.']);
  const para = chunkTtsInput('para one\n\npara two', 12);
  assert.deepEqual(para, ['para one', 'para two']);
  const words = chunkTtsInput('alpha beta gamma delta', 11);
  assert.deepEqual(words, ['alpha beta', 'gamma delta']);
  const hard = chunkTtsInput('abcdefghij', 4);
  assert.deepEqual(hard, ['abcd', 'efgh', 'ij']);
  for (const c of chunkTtsInput('x'.repeat(5000), 1200)) assert.ok(c.length <= 1200);
  assert.throws(() => chunkTtsInput('x', 0));
});

test('prepareVoxtralInput: one line, headings get a period, the last line is left alone, idempotent', () => {
  const text = 'How I Can Help\nI can do a lot!\nFor example:\n- plan a trip\n- write code\n\nAnything else?';
  const out = prepareVoxtralInput(text);
  assert.equal(out, 'How I Can Help. I can do a lot! For example: - plan a trip. - write code. Anything else?');
  assert.equal(prepareVoxtralInput(out), out);
  assert.equal(prepareVoxtralInput('a\r\nb\rc d'), 'a. b. c. d');
  assert.equal(prepareVoxtralInput('« Oui ! »\nnext'), '« Oui ! » next');
  assert.equal(prepareVoxtralInput('नमस्ते।\nnext'), 'नमस्ते। next');
});

test('chunksFor: Voxtral gets the single-line form before chunking; the others get the text as is', () => {
  const text = 'Hello!\nWorld';
  assert.deepEqual(chunksFor('tinfoil', text, 1200), ['Hello! World']);
  assert.deepEqual(chunksFor('deepgram', text, 2000), ['Hello!\nWorld']);
  assert.deepEqual(chunksFor('elevenlabs', '   ', 5000), []);
});

// ── audio ──────────────────────────────────────────────────────────────────

/** 16-bit mono PCM of a sine at `amp` (0..1), `seconds` long, as little-endian bytes. */
function sinePcm(seconds, amp, sampleRate = VOXTRAL_SAMPLE_RATE) {
  const n = Math.round(seconds * sampleRate);
  const buf = Buffer.alloc(n * 2);
  for (let i = 0; i < n; i++) buf.writeInt16LE(Math.round(Math.sin((2 * Math.PI * 220 * i) / sampleRate) * amp * 32767), i * 2);
  return buf;
}
const collect = (stream) =>
  new Promise((resolve, reject) => {
    const out = [];
    stream.on('data', (c) => out.push(c));
    stream.on('end', () => resolve(Buffer.concat(out)));
    stream.on('error', reject);
  });
const isMp3Frame = (buf) => buf.length >= 2 && buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0;

test('createPcmToMp3Transform: MP3 frames out as PCM comes in, odd bytes carried, empty in → empty out', async () => {
  const pcm = sinePcm(0.5, 0.3);
  // Odd-sized chunks split 16-bit samples across boundaries on purpose.
  const chunks = [];
  for (let i = 0; i < pcm.length; i += 1001) chunks.push(pcm.subarray(i, Math.min(i + 1001, pcm.length)));
  const t = createPcmToMp3Transform({ sampleRate: VOXTRAL_SAMPLE_RATE, level: VOXTRAL_LEVELER_PRESET });
  const frames = [];
  t.on('data', (c) => frames.push(c));
  const done = new Promise((r) => t.on('end', r));
  for (const c of chunks) t.write(c);
  t.end();
  await done;
  const mp3 = Buffer.concat(frames);
  assert.ok(frames.length > 1, 'more than one frame, so audio flowed before the end');
  assert.ok(isMp3Frame(mp3), `MP3 sync word, got ${mp3.subarray(0, 2).toString('hex')}`);
  assert.ok(mp3.length > 1000 && mp3.length < pcm.length / 4, `plausible 64 kbps size, got ${mp3.length} of ${pcm.length}`);

  const empty = await collect(Readable.from([]).pipe(createPcmToMp3Transform({ sampleRate: VOXTRAL_SAMPLE_RATE })));
  assert.equal(empty.length, 0, 'LAME would emit a padding frame; an empty upstream stays empty');
});

test('the Voxtral leveler lifts a quiet take and holds a loud one under the ceiling', async () => {
  // Levelled samples are inspected before encoding through a transform without the encoder's framing: run the leveler directly.
  const { SpeechLeveler } = await import('../src/speech.mjs');
  const quiet = new Int16Array(VOXTRAL_SAMPLE_RATE * 2);
  for (let i = 0; i < quiet.length; i++) quiet[i] = Math.round(Math.sin((2 * Math.PI * 220 * i) / VOXTRAL_SAMPLE_RATE) * 0.02 * 32767); // -34 dBFS peak
  new SpeechLeveler({ ...VOXTRAL_LEVELER_PRESET, sampleRate: VOXTRAL_SAMPLE_RATE }).process(quiet);
  const tailPeak = Math.max(...Array.from(quiet.subarray(quiet.length - 4800)).map(Math.abs)) / 32768;
  assert.ok(tailPeak > 0.05, `a quiet take is lifted (tail peak ${tailPeak.toFixed(3)})`);

  const loud = new Int16Array(VOXTRAL_SAMPLE_RATE);
  for (let i = 0; i < loud.length; i++) loud[i] = Math.round(Math.sin((2 * Math.PI * 220 * i) / VOXTRAL_SAMPLE_RATE) * 0.99 * 32767);
  new SpeechLeveler({ ...VOXTRAL_LEVELER_PRESET, sampleRate: VOXTRAL_SAMPLE_RATE }).process(loud);
  const peak = Math.max(...Array.from(loud).map(Math.abs)) / 32768;
  assert.ok(peak <= 10 ** (-1 / 20) + 0.01, `held under -1 dBFS (peak ${peak.toFixed(3)})`);
});

// ── request builders ───────────────────────────────────────────────────────

const PORTS = { 'api.deepgram.com': 9460, 'api.elevenlabs.io': 9461, 'inference.tinfoil.sh': 9456 };
const KEYS = { deepgram: 'dg-key', elevenlabs: 'el-key', tinfoil: 'tf-key' };

test('buildSpeechUpstreamRequest: Deepgram — voice as the model, MP3, training opt-out, Token auth', async () => {
  const cand = speechCandidate([{ provider: 'deepgram', api_style: 'speech', host: 'api.deepgram.com', path: '/v1/speak', key_ref: 'deepgram', upstream_model: 'aura-2-thalia-en', voice: 'aura-2-thalia-en', char_limit: 2000 }]);
  const r = await buildSpeechUpstreamRequest({ candidate: cand, text: PRIVATE_TEXT, ports: PORTS, keys: KEYS });
  assert.equal(r.output, 'mp3');
  assert.equal(r.opts.port, 9460);
  assert.equal(r.opts.servername, 'api.deepgram.com');
  assert.equal(r.opts.path, '/v1/speak?model=aura-2-thalia-en&encoding=mp3&mip_opt_out=true');
  // A candidate naming another endpoint on the same host is still sent to the one path.
  const steered = speechCandidate([{ provider: 'deepgram', api_style: 'speech', host: 'api.deepgram.com', path: '/v1/listen', key_ref: 'deepgram', upstream_model: 'v', voice: 'v', char_limit: 2000 }]);
  assert.match((await buildSpeechUpstreamRequest({ candidate: steered, text: 'x', ports: PORTS, keys: KEYS })).opts.path, /^\/v1\/speak\?/);
  assert.equal(r.opts.headers.authorization, 'Token dg-key');
  assert.deepEqual(JSON.parse(r.body.toString()), { text: PRIVATE_TEXT });
  assert.equal(r.opts.headers['content-length'], r.body.length);
});

test('buildSpeechUpstreamRequest: ElevenLabs — stream path, xi-api-key, model_id, language_code, v3 differences', async () => {
  const base = { provider: 'elevenlabs', api_style: 'speech', host: 'api.elevenlabs.io', path: '/v1/text-to-speech', key_ref: 'elevenlabs', voice: 'JBFqnCBsd6RMkjVDRZzb', char_limit: 5000 };
  const flash = speechCandidate([{ ...base, upstream_model: 'eleven_flash_v2_5', language: 'pt', speed: 1.1 }]);
  let r = await buildSpeechUpstreamRequest({ candidate: flash, text: PRIVATE_TEXT, ports: PORTS, keys: KEYS });
  assert.equal(r.opts.path, '/v1/text-to-speech/JBFqnCBsd6RMkjVDRZzb/stream?optimize_streaming_latency=3&output_format=mp3_44100_128');
  assert.equal(r.opts.headers['xi-api-key'], 'el-key');
  assert.deepEqual(JSON.parse(r.body.toString()), {
    text: PRIVATE_TEXT,
    model_id: 'eleven_flash_v2_5',
    language_code: 'pt',
    voice_settings: { stability: 0.5, similarity_boost: 0.75, speed: 1.1, style: 0, use_speaker_boost: true },
  });
  const v3 = speechCandidate([{ ...base, upstream_model: 'eleven_v3' }]);
  r = await buildSpeechUpstreamRequest({ candidate: v3, text: PRIVATE_TEXT, ports: PORTS, keys: KEYS });
  assert.equal(r.opts.path, '/v1/text-to-speech/JBFqnCBsd6RMkjVDRZzb/stream?output_format=mp3_44100_128');
  assert.deepEqual(JSON.parse(r.body.toString()).voice_settings, { stability: 0.5, similarity_boost: 0.75, speed: 1 });
});

test('buildSpeechUpstreamRequest: Voxtral — sealed to the router key, PCM stream, nothing readable on the wire', async () => {
  const router = await EhbpRecipient.generate();
  const cand = speechCandidate([{ provider: 'tinfoil', api_style: 'speech', host: 'inference.tinfoil.sh', path: '/v1/audio/speech', key_ref: 'tinfoil', upstream_model: 'voxtral-tts', voice: 'neutral_female', char_limit: 1200 }]);
  const r = await buildSpeechUpstreamRequest({ candidate: cand, text: PRIVATE_TEXT, ports: PORTS, keys: KEYS, hpkePublicKeyHex: await router.publicKeyHex() });
  assert.equal(r.output, 'pcm');
  assert.equal(r.opts.path, '/v1/audio/speech');
  assert.equal(r.opts.headers.authorization, 'Bearer tf-key');
  assert.ok(/^[0-9a-f]+$/.test(r.opts.headers['ehbp-encapsulated-key']));
  assert.equal(r.body.includes(Buffer.from('quick brown')), false, 'the text is ciphertext on the wire');
  assert.ok(r.seal.exportedSecret instanceof Uint8Array && r.seal.requestEnc instanceof Uint8Array);
  // The router can open it and sees exactly the Voxtral request.
  const opened = await router.openRequest(r.opts.headers['ehbp-encapsulated-key'], r.body);
  assert.deepEqual(JSON.parse(opened.plaintext.toString('utf8')), {
    model: VOXTRAL_UPSTREAM_MODEL,
    voice: 'neutral_female',
    input: PRIVATE_TEXT,
    response_format: 'pcm',
    stream_format: 'audio',
  });
  // Unattested: nothing is sent.
  assert.deepEqual(await buildSpeechUpstreamRequest({ candidate: cand, text: PRIVATE_TEXT, ports: PORTS, keys: KEYS }), { skip: 'tinfoil_unattested' });
});

test('buildSpeechUpstreamRequest: no tunnel or no key is a skip, never a send', async () => {
  const cand = speechCandidate([{ provider: 'deepgram', api_style: 'speech', host: 'api.deepgram.com', key_ref: 'deepgram', upstream_model: 'v', voice: 'v', char_limit: 2000 }]);
  assert.deepEqual(await buildSpeechUpstreamRequest({ candidate: cand, text: 'x', ports: {}, keys: KEYS }), { skip: 'no_tunnel_or_key' });
  assert.deepEqual(await buildSpeechUpstreamRequest({ candidate: cand, text: 'x', ports: PORTS, keys: {} }), { skip: 'no_tunnel_or_key' });
  assert.deepEqual(speechErrorBody(429), { error: { message: 'text-to-speech provider error', code: 429 } });
});
