/**
 * The PII detector, reached ONLY through its verified attestation.
 *
 * WHY
 * ---
 * The detector receives cleartext PII: that is its job. TLS to a pinned host
 * proves who operates the endpoint, not what code runs behind it. So before
 * any text leaves, the enclave verifies the detector's Tinfoil attestation
 * (SEV-SNP report + Sigstore provenance of the named config repo + matching
 * measurements, all by `@tinfoilsh/verifier`, see tinfoil.mjs) and SEALS the
 * request body with EHBP to the HPKE key that attestation vouches for. Only
 * the measured detector holds the matching private key, so the text is
 * readable by that code and nothing else — whatever the network, the TLS
 * terminator or the parent do. This is the transport the web path's Tinfoil
 * `SecureClient` uses for the same container (transport 'ehbp').
 *
 * FAIL CLOSED
 * -----------
 * No verified key, no request: an attestation that cannot be fetched or does
 * not verify (wrong measurement, wrong repo, wrong host) rejects with
 * DetectorError('attestation') before anything is sent. A reply that is not
 * sealed to this request's context cannot be opened and is 'bad_response'.
 * A 422 (the detector rotated its key) drops the cached attestation so the
 * next request re-verifies; the current one fails.
 *
 * The detection contract itself is pii/detector.mjs, unchanged: it is shared
 * byte-for-byte with the web client, which injects its own attested fetch the
 * same way this module does.
 */
import { createDetector, DetectorError, HOSTED_DETECTOR_HOST, HOSTED_DETECTOR_PATH } from './detector.mjs';
import {
  sealForTinfoil,
  createResponseOpener,
  ENCAP_KEY_HEADER,
  RESPONSE_NONCE_HEADER,
  KEY_CONFIG_MISMATCH_STATUS,
} from '../tinfoil.mjs';

/**
 * Measured placements: where each detector lives and which release its
 * attestation must prove it runs. Part of the published build, like the host
 * itself — the init blob cannot point the detector at other code. A
 * self-hosted placement is added here, with its own config repo, when it exists.
 */
export const DETECTOR_PLACEMENTS = Object.freeze({
  'tinfoil-hosted': Object.freeze({
    host: HOSTED_DETECTOR_HOST,
    path: HOSTED_DETECTOR_PATH,
    configRepo: 'tinfoilsh/confidential-pii-cpu',
  }),
});

/**
 * A fetch that seals the JSON body to `hpkePublicKeyHex` and opens the sealed
 * reply. Non-2xx answers are passed through as `{ ok: false, status }` without
 * reading their body (the detector adapter turns them into 'http_status').
 */
export function sealedFetch({ fetch: fetchImpl, hpkePublicKeyHex, onKeyMismatch = () => {} }) {
  return async function attestedFetch(url, init = {}) {
    const sealed = await sealForTinfoil(hpkePublicKeyHex, Buffer.from(String(init.body ?? ''), 'utf8'));
    const res = await fetchImpl(url, {
      ...init,
      headers: { ...(init.headers || {}), [ENCAP_KEY_HEADER]: sealed.encapHex },
      body: sealed.body,
    });
    const status = res?.status;
    if (status === KEY_CONFIG_MISMATCH_STATUS) onKeyMismatch();
    if (!res || !res.ok) return { ok: false, status };
    return {
      ok: true,
      status,
      async json() {
        const opener = await createResponseOpener({
          exportedSecret: sealed.exportedSecret,
          requestEnc: sealed.requestEnc,
          responseNonceHex: res.headers?.get?.(RESPONSE_NONCE_HEADER),
        });
        const plain = await opener.feed(Buffer.from(await res.arrayBuffer()));
        opener.finish();
        return JSON.parse(plain.toString('utf8'));
      },
    };
  };
}

/** Rejects as soon as `signal` aborts; otherwise settles with `promise`. */
function untilAborted(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new DetectorError('aborted'));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new DetectorError('aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}

/**
 * Same contract as createDetector (`detect(texts, {signal})`), with every call
 * gated on `attestor.get()` — a createTinfoilAttestor for the placement's host
 * and config repo (cached per its TTL, single-flight). There is no option to
 * skip it: without an attestor this throws bad_config.
 */
export function createAttestedDetector({ kind, url, apiKey, fetch: fetchImpl, timeoutMs, attestor } = {}) {
  if (!attestor || typeof attestor.get !== 'function' || typeof attestor.invalidate !== 'function') {
    throw new DetectorError('bad_config');
  }
  const detectorFor = (hpkePublicKeyHex) =>
    createDetector({
      kind,
      url,
      apiKey,
      timeoutMs,
      fetch: sealedFetch({ fetch: fetchImpl, hpkePublicKeyHex, onKeyMismatch: () => attestor.invalidate() }),
    });
  // Validates the configuration up front (throws bad_config), as createDetector does.
  const probe = createDetector({ kind, url, apiKey, timeoutMs, fetch: fetchImpl });

  return {
    kind: probe.kind,
    timeoutMs: probe.timeoutMs,
    attestation: () => attestor.state?.() ?? null,
    async detect(texts, { signal } = {}) {
      // Nothing to send ⇒ nothing to attest (and no request is made).
      if (Array.isArray(texts) && texts.every((t) => typeof t === 'string' && t.trim() === '')) {
        return probe.detect(texts, { signal });
      }
      let verified;
      try {
        verified = await untilAborted(attestor.get(), signal);
      } catch (e) {
        if (e instanceof DetectorError) throw e;
        throw new DetectorError('attestation');
      }
      const key = String(verified?.hpkePublicKeyHex || '');
      if (!/^[0-9a-f]{64}$/.test(key)) throw new DetectorError('attestation');
      // Sealed to exactly the key that was just verified: no second lookup
      // that could land on a different (or expired) attestation mid-call.
      return detectorFor(key).detect(texts, { signal });
    },
  };
}
