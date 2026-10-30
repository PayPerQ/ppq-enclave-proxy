/**
 * `/v1/audio/speech` — text-to-speech, served IN the enclave (#397) so the
 * text a user has read aloud is as private as the chat that produced it.
 *
 * Until this route existed the speaker button in the web app, and every API
 * TTS call, posted the text to this path and the enclave proxied it to
 * horse-power in the clear: an answer generated privately a moment earlier
 * left the enclave the instant someone wanted to hear it. Now horse-power
 * learns the model, the voice, the language, the ElevenLabs speed and a
 * CHARACTER COUNT at `/enclave/authorize` (never the text), answers with the
 * one provider candidate (`api_style: 'speech'`, carrying the voice it
 * resolved and the chunk limit), and the settle carries the character and
 * chunk counts it prices from.
 *
 * Three providers, one handler:
 *  - Voxtral on Tinfoil's confidential router: the request is sealed to the
 *    router's attested HPKE key exactly as a `private/*` chat body is
 *    (tinfoil.mjs), so neither PayPerQ nor the speech provider sees the text.
 *    The router streams raw 24 kHz PCM; it is levelled and encoded to MP3 in
 *    here, frame by frame, because the route's contract is streamed
 *    `audio/mpeg` and the model's raw output is unmastered (horse-power
 *    #1183) and misreads line breaks (#1185).
 *  - Deepgram Aura and ElevenLabs over their own tunnels: the provider sees
 *    the text, as it always has; PayPerQ does not.
 *
 * This module holds the pure parts: the validator, the authorize measure, the
 * chunker and the Voxtral text form (ported from horse-power's
 * utils/ttsChunker.ts and utils/voxtralText.ts), the speech leveler and the
 * PCM→MP3 transform (utils/speechLeveler.ts, utils/pcmToMp3.ts), and the
 * per-provider request builders. server.mjs owns the handler (it needs the
 * tunnels, the attestor, EHBP and the settle queue).
 *
 * Everything returned to hp is a count or a closed value: no content leaves.
 */
import { Transform } from 'node:stream';
import { Mp3Encoder } from '@breezystack/lamejs';
import { sealForTinfoil } from './tinfoil.mjs';

/** Where the client posts. */
export const SPEECH_PATH = '/v1/audio/speech';
/** What `/enclave/authorize` and `/enclave/settle` learn about the request. */
export const SPEECH_ENDPOINT = 'speech';
/** `cost_source` on the settle: hp prices from the counts, nothing is read off the wire. */
export const SPEECH_COST_SOURCE = 'speech-chars';
/** hp's candidate dialect for this route (services/enclaveUpstreams buildSpeechUpstreams). */
export const SPEECH_API_STYLE = 'speech';
/** The providers hp may name; anything else is refused before any send. */
export const SPEECH_PROVIDERS = Object.freeze(['tinfoil', 'deepgram', 'elevenlabs']);

export const DEEPGRAM_HOST = 'api.deepgram.com';
export const ELEVENLABS_HOST = 'api.elevenlabs.io';
/**
 * The one path each provider is spoken to on. Constants, not hp's `path`: the
 * host/key/provider binding stops an arbitrary host, and this stops a
 * compromised horse-power from steering the text and the provider's key to
 * another endpoint on an allowed host.
 */
export const DEEPGRAM_SPEAK_PATH = '/v1/speak';
export const ELEVENLABS_TTS_PATH = '/v1/text-to-speech';

/** The one input bound both doors apply (horse-power services/speechEndpoint MAX_TTS_INPUT_CHARS). */
export const MAX_TTS_INPUT_CHARS = 50_000;
/**
 * 50,000 characters is at most 200 KB of UTF-8, plus the sealing frame; one
 * request never needs more than this, and the cap bounds what one sealed
 * request may ask this worker to hold.
 */
export const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
/** A provider error body is read up to this; the rest is dropped. */
export const MAX_ERROR_BODY_BYTES = 64 * 1024;

/** Voxtral's wire id on Tinfoil's router and its PCM sample rate. */
export const VOXTRAL_UPSTREAM_MODEL = 'voxtral-tts';
export const VOXTRAL_SAMPLE_RATE = 24_000;

/** Per-provider chunk limit when hp's candidate carries none (an older hp). */
export const DEFAULT_CHAR_LIMIT = Object.freeze({ tinfoil: 1200, deepgram: 2000, elevenlabs: 5000 });

const isPlainRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// A voice id as the three providers mint them (Deepgram `aura-2-thalia-en`,
// ElevenLabs 20-char alphanumerics, Voxtral `de_male`); bounded so the value
// never reaches a URL or a log line unshaped. Mirror of hp's VOICE_ID_RE.
const VOICE_ID_RE = /^[\w.-]{1,128}$/;
const LANGUAGE_MAX = 32;
// The creator-payout tool id, in the one shape hp's payout accepts.
const TOOL_ID_RE = /^[\w:.-]{1,64}$/;

/**
 * Validate a speech body — only as far as the enclave needs, and never
 * echoing a value: the field names and messages are content-free by
 * construction. `language_code` is accepted as the alias horse-power's direct
 * handler takes.
 *
 * Returns `{ kind: 'ok', value: { input, model, voice?, language?, speed?, tool_id? } }`
 * or `{ kind: 'invalid', error: { field, message } }`.
 */
export function validateSpeechRequest(body) {
  const fail = (field, message) => ({ kind: 'invalid', error: { field, message } });
  if (!isPlainRecord(body)) return fail('body', 'Request body must be a JSON object');

  const { input, model, voice, speed, tool_id } = body;
  if (typeof model !== 'string' || model.trim() === '' || model.length > 256) {
    return fail('model', '`model` is required');
  }
  if (typeof input !== 'string' || input.trim() === '') {
    return fail('input', '`input` is required and must contain non-whitespace text');
  }
  if (input.length > MAX_TTS_INPUT_CHARS) {
    return fail('input', `Input exceeds maximum length of ${MAX_TTS_INPUT_CHARS} characters`);
  }
  const value = { input, model: model.trim() };

  if (voice !== undefined && voice !== null) {
    if (typeof voice !== 'string' || !VOICE_ID_RE.test(voice.trim())) {
      return fail('voice', '`voice` must be a voice id');
    }
    value.voice = voice.trim();
  }
  const rawLanguage = body.language ?? body.language_code;
  if (rawLanguage !== undefined && rawLanguage !== null && String(rawLanguage).trim() !== '') {
    if (typeof rawLanguage !== 'string' || rawLanguage.length > LANGUAGE_MAX) {
      return fail('language', '`language` must be an ISO 639-1 code');
    }
    value.language = rawLanguage.trim();
  }
  if (speed !== undefined && speed !== null) {
    if (typeof speed !== 'number' || !Number.isFinite(speed) || speed <= 0 || speed > 10) {
      return fail('speed', '`speed` must be a number');
    }
    value.speed = speed;
  }
  if (tool_id !== undefined && tool_id !== null) {
    if (typeof tool_id !== 'string' || !TOOL_ID_RE.test(tool_id)) {
      return fail('tool_id', '`tool_id` must be a string when provided');
    }
    value.tool_id = tool_id;
  }
  return { kind: 'ok', value };
}

/**
 * What hp learns at authorize: the endpoint, the sizes, and the three values
 * it resolves the voice and prices the request from. Counts and ids only.
 */
export function measureSpeechInput(request) {
  return {
    endpoint: SPEECH_ENDPOINT,
    input_bytes: Buffer.byteLength(request.input, 'utf8'),
    input_chars: request.input.length,
    ...(request.voice ? { voice: request.voice } : {}),
    ...(request.language ? { language: request.language } : {}),
    ...(typeof request.speed === 'number' ? { speed: request.speed } : {}),
  };
}

/**
 * The one speech candidate out of hp's list, or null. hp sends exactly one
 * (no OpenRouter terminal: nothing else can speak in a provider's voice), so
 * anything but a single well-formed `api_style: 'speech'` entry naming a
 * known provider is "no route" — a refusal, never a guess.
 */
export function speechCandidate(upstreams) {
  if (!Array.isArray(upstreams) || upstreams.length !== 1) return null;
  const c = upstreams[0];
  if (!isPlainRecord(c) || c.api_style !== SPEECH_API_STYLE) return null;
  if (!SPEECH_PROVIDERS.includes(c.provider)) return null;
  if (typeof c.voice !== 'string' || !VOICE_ID_RE.test(c.voice)) return null;
  if (typeof c.host !== 'string' || !c.host || typeof c.key_ref !== 'string') return null;
  const limit = Number.isInteger(c.char_limit) && c.char_limit > 0 ? c.char_limit : DEFAULT_CHAR_LIMIT[c.provider];
  // hp's `path` is deliberately not read: the paths are constants above.
  return {
    provider: c.provider,
    // Kept: the binding check (upstreamBinding.mjs) judges the dialect too.
    api_style: SPEECH_API_STYLE,
    host: c.host,
    key_ref: c.key_ref,
    upstream_model: typeof c.upstream_model === 'string' ? c.upstream_model : '',
    voice: c.voice,
    char_limit: limit,
    language: typeof c.language === 'string' && c.language.length <= LANGUAGE_MAX ? c.language : undefined,
    speed: typeof c.speed === 'number' && Number.isFinite(c.speed) ? c.speed : undefined,
  };
}

// ─── Text ────────────────────────────────────────────────────────────────────

/**
 * Splits TTS input into chunks no longer than `maxChars`, preferring natural
 * boundaries (paragraph → sentence → whitespace → hard cut). Empty and
 * whitespace-only pieces are skipped. Port of horse-power utils/ttsChunker.ts.
 */
export function chunkTtsInput(text, maxChars) {
  if (!(maxChars > 0)) throw new Error('maxChars must be positive');
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed.length <= maxChars) return [trimmed];

  const chunks = [];
  let remaining = trimmed;
  while (remaining.length > maxChars) {
    const window = remaining.slice(0, maxChars);
    const cutAt = findSplitPoint(window);
    const head = remaining.slice(0, cutAt).trim();
    if (head) chunks.push(head);
    remaining = remaining.slice(cutAt).trimStart();
  }
  if (remaining.trim()) chunks.push(remaining.trim());
  return chunks;
}

const PARAGRAPH_RE = /\n\s*\n/g;
const SENTENCE_RE = /[.!?…。！？]["')\]]?\s+/g;

function findSplitPoint(window) {
  const paragraph = lastIndexOfRegex(window, PARAGRAPH_RE);
  if (paragraph !== -1) return paragraph + matchedLength(window, paragraph, PARAGRAPH_RE);
  const sentence = lastIndexOfRegex(window, SENTENCE_RE);
  if (sentence !== -1) return sentence + matchedLength(window, sentence, SENTENCE_RE);
  const whitespace = window.lastIndexOf(' ');
  if (whitespace > 0) return whitespace + 1;
  return window.length;
}

function lastIndexOfRegex(haystack, pattern) {
  const re = new RegExp(pattern.source, 'g');
  let last = -1;
  let m;
  while ((m = re.exec(haystack)) !== null) {
    last = m.index;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return last;
}

function matchedLength(haystack, fromIndex, pattern) {
  const re = new RegExp(pattern.source, 'g');
  re.lastIndex = fromIndex;
  const m = re.exec(haystack);
  return m && m.index === fromIndex ? m[0].length : 1;
}

// Sentence and clause marks for the languages Voxtral voices cover (Latin
// scripts, Arabic, Devanagari) plus CJK and fullwidth forms, optionally
// followed by closing quotes or brackets, which French typography separates
// with a space.
const ENDS_WITH_PUNCTUATION = /[.!?:;,…؟،؛।॥。！？：；，、](?:\s*["'\p{Pe}\p{Pf}])*$/u;

/**
 * Rewrites text into a single line before it goes to Voxtral. Voxtral misreads
 * a line break after an exclamation mark ("exclamation" repeated, or the next
 * sentence dropped, in about half of takes — horse-power #1184/#1185), so every
 * line break becomes a space, and a line with no closing punctuation (a
 * heading, a list item) gets a period so it is still read as its own phrase.
 * The last line is left as is. Idempotent. Applied BEFORE chunking so the
 * chunk limit holds for the exact text sent upstream.
 */
export function prepareVoxtralInput(text) {
  return text
    .split(/(?:\r\n|[\n\r\u2028\u2029])+/)
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .map((line, i, lines) => (i === lines.length - 1 || ENDS_WITH_PUNCTUATION.test(line) ? line : `${line}.`))
    .join(' ');
}

/** The text a provider is sent, split into upstream requests. */
export function chunksFor(provider, input, charLimit) {
  const text = provider === 'tinfoil' ? prepareVoxtralInput(input) : input;
  return chunkTtsInput(text, charLimit);
}

// ─── Audio ───────────────────────────────────────────────────────────────────

/**
 * Calibration for Voxtral TTS, measured 2026-10-29 on nine real takes
 * (horse-power #1182): typical takes land at -21 to -24 LUFS (Deepgram Aura-2
 * is about -25), the limiter cuts more than 1 dB on none of their samples, and
 * a rare loud take is held under -1 dBFS. `initialLevelDb` is a property of
 * the source: a different model needs its own preset.
 */
export const VOXTRAL_LEVELER_PRESET = Object.freeze({
  targetDb: -20,
  initialLevelDb: -30,
  minGainDb: -6,
  maxGainDb: 18,
  ceilingDb: -1,
  gateDb: -50,
  levelTimeMs: 1500,
  gainTimeMs: 150,
  releaseMs: 250,
});

const dbToAmp = (db) => 10 ** (db / 20);
const coef = (ms, perSecond) => Math.exp(-1000 / (ms * perSecond));

/**
 * Streaming loudness leveler for synthesized speech (16-bit PCM), adding no
 * latency: a slow automatic gain control on 20 ms blocks above a silence gate,
 * then an instant-attack peak limiter under `ceilingDb`. Port of horse-power
 * utils/speechLeveler.ts; see that file for the measurements behind it.
 */
export class SpeechLeveler {
  constructor(opts) {
    const sr = opts.sampleRate;
    this.blockLen = Math.max(1, Math.round(sr * 0.02));
    this.targetMs = dbToAmp(opts.targetDb) ** 2;
    this.gateMs = dbToAmp(opts.gateDb) ** 2;
    this.minGain = dbToAmp(opts.minGainDb);
    this.maxGain = dbToAmp(opts.maxGainDb);
    this.ceiling = dbToAmp(opts.ceilingDb);
    this.levelCoef = coef(opts.levelTimeMs, sr / this.blockLen);
    this.gainCoef = coef(opts.gainTimeMs, sr);
    this.releaseCoef = coef(opts.releaseMs, sr);
    this.levelMs = dbToAmp(opts.initialLevelDb) ** 2;
    this.desiredGain = this.computeGain();
    this.gain = this.desiredGain;
    this.env = 0;
    this.blockSum = 0;
    this.blockCount = 0;
  }

  computeGain() {
    const g = Math.sqrt(this.targetMs / this.levelMs);
    return Math.min(this.maxGain, Math.max(this.minGain, g));
  }

  /** Levels `samples` (Int16Array) in place. */
  process(samples) {
    for (let i = 0; i < samples.length; i++) {
      const x = samples[i] / 32768;
      this.blockSum += x * x;
      if (++this.blockCount === this.blockLen) {
        const blockMs = this.blockSum / this.blockLen;
        if (blockMs > this.gateMs) {
          this.levelMs = this.levelCoef * this.levelMs + (1 - this.levelCoef) * blockMs;
          this.desiredGain = this.computeGain();
        }
        this.blockSum = 0;
        this.blockCount = 0;
      }
      this.gain = this.gainCoef * this.gain + (1 - this.gainCoef) * this.desiredGain;
      const y = x * this.gain;
      const peak = Math.abs(y);
      this.env = peak > this.env ? peak : this.env * this.releaseCoef;
      const limited = this.env > this.ceiling ? y * (this.ceiling / this.env) : y;
      const s = Math.round(limited * 32768);
      samples[i] = s > 32767 ? 32767 : s < -32768 ? -32768 : s;
    }
    return samples;
  }
}

/**
 * Streaming PCM (16-bit signed little-endian mono) → MP3 Transform. The first
 * MP3 frame goes out as soon as the first PCM chunk lands, which is what keeps
 * Voxtral's sub-second time to first audio. `level` runs the leveler first.
 * 64 kbps mono is transparent for speech. Port of horse-power utils/pcmToMp3.ts.
 */
export function createPcmToMp3Transform({ sampleRate, kbps = 64, level = null }) {
  const encoder = new Mp3Encoder(1, sampleRate, kbps);
  const leveler = level ? new SpeechLeveler({ ...level, sampleRate }) : null;
  // lamejs returns Int8Array views; re-wrap the same bytes as a Buffer.
  const asBuffer = (frames) => Buffer.from(frames.buffer, frames.byteOffset, frames.byteLength);
  // A chunk boundary can split a 16-bit sample; the odd byte waits.
  let carry = null;
  let encodedAny = false;
  return new Transform({
    transform(chunk, _enc, cb) {
      try {
        let bytes = carry ? Buffer.concat([carry, chunk]) : chunk;
        carry = null;
        const even = bytes.length - (bytes.length % 2);
        if (even < bytes.length) carry = Buffer.from(bytes.subarray(even));
        if (even === 0) return cb();
        const samples = new Int16Array(even / 2);
        for (let i = 0; i < samples.length; i++) samples[i] = bytes.readInt16LE(i * 2);
        leveler?.process(samples);
        encodedAny = true;
        const mp3 = encoder.encodeBuffer(samples);
        cb(null, mp3.byteLength > 0 ? asBuffer(mp3) : undefined);
      } catch (e) {
        cb(e);
      }
    },
    flush(cb) {
      try {
        // LAME emits a padding frame on flush even with no input; an empty
        // upstream stays empty downstream.
        if (!encodedAny) return cb();
        const tail = encoder.flush();
        cb(null, tail.byteLength > 0 ? asBuffer(tail) : undefined);
      } catch (e) {
        cb(e);
      }
    },
  });
}

// ─── Request builders ────────────────────────────────────────────────────────

const ELEVENLABS_VOICE_DEFAULTS = Object.freeze({ stability: 0.5, similarity_boost: 0.75, style: 0.0, use_speaker_boost: true });

/**
 * The outbound request for one chunk of text, or `{ skip }` when the tunnel
 * or the key is missing. The provider's own wire, as horse-power's adapters
 * speak it (services/providers/deepgramProvider.ts, elevenlabsProvider.ts,
 * tinfoilTtsProvider.ts):
 *
 *  - Deepgram: `POST /v1/speak?model=<voice>&encoding=mp3&mip_opt_out=true`
 *    (never let Deepgram keep the text for training, horse-power #1178),
 *    `Authorization: Token`, body `{"text"}`; MP3 back.
 *  - ElevenLabs: `POST /v1/text-to-speech/<voice>/stream?...`, `xi-api-key`,
 *    body `{text, model_id, language_code?, voice_settings}`; MP3 back. v3
 *    takes neither `optimize_streaming_latency` nor style/speaker boost.
 *  - Tinfoil (Voxtral): `POST /v1/audio/speech` with
 *    `{model, voice, input, response_format: 'pcm', stream_format: 'audio'}`,
 *    sealed to the router's attested HPKE key; raw PCM back under a sealed
 *    stream. The caller decrypts (tinfoil.mjs) and runs `createPcmToMp3Transform`.
 *
 * @returns {Promise<{opts, body, output: 'mp3'|'pcm', seal?}|{skip: string}>}
 */
export async function buildSpeechUpstreamRequest({ candidate, text, ports, keys, hpkePublicKeyHex = null }) {
  const port = ports[candidate.host] ?? ports[candidate.provider];
  const key = keys[candidate.key_ref];
  if (!port || !key) return { skip: 'no_tunnel_or_key' };
  const base = (path, headers, body) => ({
    opts: {
      host: '127.0.0.1',
      port,
      servername: candidate.host,
      method: 'POST',
      path,
      headers: { host: candidate.host, 'content-type': 'application/json', 'content-length': body.length, ...headers },
    },
    body,
  });

  if (candidate.provider === 'deepgram') {
    const body = Buffer.from(JSON.stringify({ text }));
    const path = `${DEEPGRAM_SPEAK_PATH}?model=${encodeURIComponent(candidate.voice)}&encoding=mp3&mip_opt_out=true`;
    return { ...base(path, { authorization: `Token ${key}` }, body), output: 'mp3' };
  }
  if (candidate.provider === 'elevenlabs') {
    const modelId = candidate.upstream_model;
    const isV3 = modelId === 'eleven_v3';
    const query = isV3 ? 'output_format=mp3_44100_128' : 'optimize_streaming_latency=3&output_format=mp3_44100_128';
    const path = `${ELEVENLABS_TTS_PATH}/${encodeURIComponent(candidate.voice)}/stream?${query}`;
    const voiceSettings = {
      stability: ELEVENLABS_VOICE_DEFAULTS.stability,
      similarity_boost: ELEVENLABS_VOICE_DEFAULTS.similarity_boost,
      speed: typeof candidate.speed === 'number' ? candidate.speed : 1.0,
      ...(isV3 ? {} : { style: ELEVENLABS_VOICE_DEFAULTS.style, use_speaker_boost: ELEVENLABS_VOICE_DEFAULTS.use_speaker_boost }),
    };
    const body = Buffer.from(
      JSON.stringify({
        text,
        model_id: modelId,
        ...(candidate.language ? { language_code: candidate.language } : {}),
        voice_settings: voiceSettings,
      }),
    );
    return { ...base(path, { 'xi-api-key': key }, body), output: 'mp3' };
  }
  // Tinfoil: sealed to the router's key, or nothing is sent.
  if (!hpkePublicKeyHex) return { skip: 'tinfoil_unattested' };
  const plaintext = Buffer.from(
    JSON.stringify({
      model: candidate.upstream_model || VOXTRAL_UPSTREAM_MODEL,
      voice: candidate.voice,
      input: text,
      response_format: 'pcm',
      stream_format: 'audio',
    }),
  );
  const sealed = await sealForTinfoil(hpkePublicKeyHex, plaintext);
  return {
    ...base(
      SPEECH_PATH,
      { authorization: `Bearer ${key}`, 'ehbp-encapsulated-key': sealed.encapHex },
      sealed.body,
    ),
    output: 'pcm',
    seal: { exportedSecret: sealed.exportedSecret, requestEnc: sealed.requestEnc },
  };
}

/** The error body a refused provider answer is replaced with when it cannot be relayed as JSON. */
export function speechErrorBody(status) {
  return { error: { message: 'text-to-speech provider error', code: status } };
}
