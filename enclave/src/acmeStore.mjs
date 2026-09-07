// Seals the ACME-issued certificate so it can survive an enclave restart while
// living on storage the parent owns and cannot read.
//
// WHY THIS EXISTS
// ---------------
// The enclave has no disk. Everything it holds is in memory and dies with the
// process, and the enclave is rotated roughly seven times a week. Without a
// store, every restart places a fresh ACME order -- and Let's Encrypt allows
// five DUPLICATE certificates per week for an identical name set. Production
// would be exhausted in a day, leaving us unable to obtain a certificate for
// the remainder of the window, with no way to undo it. That is why in-enclave
// ACME shipped dormant in v0.7.0 and why this file is the gate (#83).
//
// WHAT THE FIELD DOES, AND WHY WE CANNOT COPY IT VERBATIM
// ------------------------------------------------------
// Tinfoil's `tfshim` writes `cert.pem` (0644) and `key.pem` (0600) to a plain
// cache directory and, on boot, loads them and skips ACME entirely. No sealing.
// It can do that because Tinfoil runs on AMD SEV confidential VMs, where the
// encrypted disk is INSIDE the trust boundary -- disk is part of the enclave.
// Brave's nitriding, the AWS Nitro reference, implements its autocert cache as
// an in-memory map and persists nothing, so it has exactly the gap this closes.
//
// Nitro gives us no storage inside the boundary at all, so the cache has to
// live on the parent. If the parent could read the certificate's private key it
// could terminate TLS and impersonate the enclave -- precisely the property the
// TLS-in-enclave epic (#52) exists to establish. So the cache is the same idea
// as Tinfoil's directory, sealed on the way out.
//
// WHY ENVELOPE ENCRYPTION RATHER THAN "ENCRYPT UNDER THE CMK"
// ----------------------------------------------------------
// The enclave cannot encrypt. `kmstool_enclave_cli` v0.4.2 exposes exactly
// three verbs -- `decrypt`, `genkey`, `genrandom` -- and there is no `encrypt`.
// So sealing goes through `genkey` (KMS GenerateDataKey), which returns a data
// key BOTH in the clear and wrapped under the CMK. We encrypt locally with the
// clear copy, keep the wrapped one, and drop the clear one.
//
// Unsealing calls `decrypt` on the wrapped key, and THAT is the attestation-
// gated step: the CMK releases it only to a caller whose PCR0 is on the key
// policy's allow-list.
//
// ROTATION IS ALREADY HANDLED, WHICH IS WORTH STATING
// ---------------------------------------------------
// `kms:RecipientAttestation:PCR0` constrains the CALLER at decrypt time, not
// whatever produced the blob. The cutover already grants an incoming
// measurement BEFORE the swap and keeps {running, previous} (#84), so a new
// image unseals a blob the previous image sealed with no extra machinery. A
// store bound to the sealing measurement would have needed that machinery; this
// one does not.
//
// NO KMS ENCRYPTION CONTEXT -- read this before assuming there is one
// -------------------------------------------------------------------
// The obvious hardening is a KMS EncryptionContext of {purpose, domain} so a
// data key minted for this store cannot be spent anywhere else, enforced by KMS
// on decrypt. `kmstool_enclave_cli` accepts no `--encryption-context` flag (see
// its option table), so that is simply not reachable from inside an enclave
// using this tool. The domain and version are bound as AES-GCM additional
// authenticated data instead, which stops the header being edited under the
// ciphertext but is NOT equivalent: it is enforced by us, not by KMS.
//
// The residual risk that leaves is REPLAY, and it is the parent's to attempt: it
// may hand back an older sealed blob it kept, pinning the enclave to a
// certificate it genuinely held once. EncryptionContext would not have stopped
// that either -- the blob is authentic. `isUsable()` below bounds it by
// rejecting material that is expired or for the wrong name, which reduces the
// attack to "serve a certificate we legitimately held, until it expires."
// Closing it completely needs state the parent cannot roll back, which means
// external storage, and that is deliberately out of scope here.

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';

/** Bumped only if the sealed layout changes; an unknown version is refused. */
export const STORE_VERSION = 1;

const KMSTOOL_BIN = '/usr/bin/kmstool_enclave_cli';
const CIPHER = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Run kmstool and return stdout.
 *
 * Credentials ride argv here because kmstool offers no other way to accept
 * them. That is safe ONLY because this runs inside the enclave, where the
 * process table is not shared with anything outside the trust boundary -- the
 * same reasoning boot.sh already relies on. Do not lift this helper to the
 * parent.
 */
function runKmstool(args, { bin = KMSTOOL_BIN, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`kmstool ${args[0]} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        // stderr only. kmstool prints key material on STDOUT, so echoing that
        // into an error -- which callers log -- would leak the data key.
        // The exit code and whether stderr said ANYTHING are both signal: an
        // abort (134) means an assertion inside the SDK, a clean 1 with empty
        // stderr means it gave up before printing, and the SDK only prints its
        // `Got non-200` line once the HTTP call has actually happened.
        const tail = err.trim();
        reject(new Error(
          `kmstool ${args[0]} exited ${code} stderr=${tail ? 'present' : 'empty'}: ${tail}`,
        ));
      } else {
        resolve(out);
      }
    });
  });
}

/**
 * Pull a labelled base64 field out of kmstool's stdout.
 *
 * Output is line-oriented `LABEL: <base64>`. `genkey` prints CIPHERTEXT and
 * PLAINTEXT; `decrypt` prints only PLAINTEXT.
 */
export function parseKmstoolField(stdout, label) {
  for (const line of String(stdout).split('\n')) {
    const prefix = `${label}: `;
    if (line.startsWith(prefix)) return line.slice(prefix.length).trim();
  }
  throw new Error(`kmstool output had no ${label} field`);
}

export function credentialArgs({ region, proxyPort, accessKeyId, secretAccessKey, sessionToken }) {
  const args = [
    '--region', region,
    '--proxy-port', String(proxyPort),
    '--aws-access-key-id', accessKeyId,
    '--aws-secret-access-key', secretAccessKey,
  ];
  // ALWAYS pass the flag, even empty. kmstool rejects a MISSING session token
  // outright -- `--aws-session-token must be set`, exit 1 -- and then
  // dereferences the value unconditionally in init_kms_client, so omitting it
  // is the one thing that cannot work. boot.sh has always passed it
  // unconditionally; this helper diverged from that and every genkey call died
  // on the argument check before reaching KMS, which is why decrypt worked and
  // genkey did not (#83).
  args.push('--aws-session-token', sessionToken || '');
  return args;
}

/**
 * The exact argv for each kmstool call, exported so the SHAPE is asserted
 * rather than assumed.
 *
 * Both bugs in this file were divergences from boot.sh's invocation, not logic
 * errors: a conditionally-omitted session token, and a `--key-id` on decrypt
 * that boot.sh never sends. Neither showed up in any unit test, because the
 * tests substituted the KMS backend wholesale and never looked at the command.
 */
export function genkeyArgs(creds) {
  return ['genkey', ...credentialArgs(creds), '--key-id', creds.keyId, '--key-spec', 'AES-256'];
}

export function decryptArgs(creds, ciphertextB64) {
  return ['decrypt', ...credentialArgs(creds), '--ciphertext', ciphertextB64];
}

/**
 * The two KMS calls this module needs, isolated so tests can substitute them.
 *
 * Neither is exercisable outside production: a dev enclave has a different PCR0
 * and can never satisfy the production CMK's attestation condition
 * (DEV-ENCLAVE.md). Keeping the boundary this narrow is what makes the rest of
 * the file testable at all.
 */
export function kmstoolBackend(creds) {
  return {
    async generateDataKey() {
      const out = await runKmstool(genkeyArgs(creds));
      return {
        plaintextB64: parseKmstoolField(out, 'PLAINTEXT'),
        ciphertextB64: parseKmstoolField(out, 'CIPHERTEXT'),
      };
    },
    async decryptDataKey(ciphertextB64) {
      // NO --key-id, deliberately. boot.sh decrypts four provider secrets this
      // way in production on every boot, and that is the invocation known to
      // work. kmstool forwards key_id AND encryption_algorithm straight to
      // aws_kms_decrypt_blocking; supplying one without the other made every
      // unseal fail with "Could not decrypt ciphertext" (#83). A symmetric CMK
      // needs neither -- KMS identifies the key from the ciphertext blob.
      //
      // The rule this cost us twice: MIRROR boot.sh's invocation exactly.
      // Both bugs here were places this helper "improved" on it.
      const out = await runKmstool(decryptArgs(creds, ciphertextB64));
      return parseKmstoolField(out, 'PLAINTEXT');
    },
  };
}

/** The cleartext header, also bound as AAD so it cannot be edited underneath. */
function aad(header) {
  return Buffer.from(JSON.stringify({ v: header.v, domain: header.domain }), 'utf8');
}

/**
 * Seal `payload` into a blob safe to hand to the parent.
 *
 * `payload` must carry `domain`; it is repeated in the cleartext header so an
 * operator can tell two files apart, and cross-checked on the way back in.
 */
export async function sealStore(payload, { kms, domain = payload?.domain } = {}) {
  if (!kms) throw new Error('sealStore requires a kms backend');
  if (!domain) throw new Error('sealStore requires a domain');

  const { plaintextB64, ciphertextB64 } = await kms.generateDataKey();
  const dek = Buffer.from(plaintextB64, 'base64');
  try {
    if (dek.length !== 32) throw new Error(`expected a 32-byte data key, got ${dek.length}`);
    const iv = crypto.randomBytes(IV_BYTES);
    const header = { v: STORE_VERSION, alg: CIPHER, domain, wrappedDek: ciphertextB64, iv: iv.toString('base64') };
    const cipher = crypto.createCipheriv(CIPHER, dek, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aad(header));
    const body = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify({ ...payload, domain }), 'utf8')),
      cipher.final(),
    ]);
    return { ...header, tag: cipher.getAuthTag().toString('base64'), ciphertext: body.toString('base64') };
  } finally {
    // The wrapped copy is what persists; this one must not linger in the heap
    // any longer than the encryption needed it.
    dek.fill(0);
  }
}

/**
 * Open a blob produced by `sealStore`.
 *
 * Throws on anything unexpected rather than returning a partial result: a store
 * that cannot be trusted must send the caller down the "order a new
 * certificate" path, not hand back half a certificate.
 */
export async function unsealStore(blob, { kms } = {}) {
  if (!kms) throw new Error('unsealStore requires a kms backend');
  if (!blob || typeof blob !== 'object') throw new Error('store blob is not an object');
  if (blob.v !== STORE_VERSION) throw new Error(`unsupported store version ${blob.v}`);
  if (blob.alg !== CIPHER) throw new Error(`unsupported store algorithm ${blob.alg}`);
  for (const field of ['domain', 'wrappedDek', 'iv', 'tag', 'ciphertext']) {
    if (typeof blob[field] !== 'string' || !blob[field]) {
      throw new Error(`store blob is missing ${field}`);
    }
  }

  const dek = Buffer.from(await kms.decryptDataKey(blob.wrappedDek), 'base64');
  try {
    if (dek.length !== 32) throw new Error(`expected a 32-byte data key, got ${dek.length}`);
    const decipher = crypto.createDecipheriv(
      CIPHER, dek, Buffer.from(blob.iv, 'base64'), { authTagLength: TAG_BYTES },
    );
    decipher.setAAD(aad(blob));
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, 'base64')),
      decipher.final(),
    ]);
    const payload = JSON.parse(plain.toString('utf8'));
    // The header is attacker-visible and the payload is not; a mismatch means
    // the two were assembled from different seals.
    if (payload.domain !== blob.domain) {
      throw new Error('sealed domain does not match the blob header');
    }
    return payload;
  } finally {
    dek.fill(0);
  }
}

/** Renew this far ahead of expiry. 30d of a 90d certificate is the norm. */
export const RENEW_BEFORE_MS = 30 * 86_400_000;

/**
 * Whether unsealed material can be served at all.
 *
 * Deliberately separate from `needsRenewal`, and the split matters: a
 * certificate inside its renewal window is still perfectly good to serve. If
 * one predicate answered both questions, a renewal that failed -- Let's
 * Encrypt down, a network blip -- would drop TLS entirely rather than keep
 * serving a certificate that is valid for another month.
 *
 * This is also the bound on the replay risk described at the top of the file:
 * the parent may re-present an older blob, so age is checked rather than
 * trusted. The margin stops a certificate expiring mid-handshake.
 */
export function isServable(
  payload,
  { domain, domains, directoryUrl, now = Date.now(), marginMs = 300_000 } = {},
) {
  if (!payload || typeof payload !== 'object') return false;
  if (typeof payload.cert !== 'string' || !payload.cert) return false;
  if (typeof payload.key !== 'string' || !payload.key) return false;
  // A certificate from a DIFFERENT ACME directory is not servable, even though
  // it is a perfectly valid certificate for the right name and still in date.
  //
  // Without this, flipping ACME_DIRECTORY from staging to production is a
  // silent no-op: the stored STAGING certificate still passes every other
  // check, so no order is placed and the enclave keeps serving a certificate
  // no browser trusts -- with nothing in the logs to say why. A blob sealed
  // before this field existed has no `directoryUrl`, and is accepted so an
  // upgrade does not spend an order it did not need to.
  if (directoryUrl && payload.directoryUrl && payload.directoryUrl !== directoryUrl) return false;
  // A stored certificate may cover several names (SAN). It is servable only if
  // it covers EVERY name we now intend to serve -- a cert for the shadow name
  // alone must not be accepted once production is added, or the enclave would
  // serve a certificate that does not match the name a browser asked for.
  const covered = payload.domains?.length ? payload.domains : [payload.domain];
  const wanted = domains?.length ? domains : (domain ? [domain] : []);
  if (wanted.some((n) => !covered.includes(n))) return false;
  const notAfter = Date.parse(payload.notAfter);
  if (!Number.isFinite(notAfter)) return false;
  return notAfter - now > marginMs;
}

/**
 * Whether to order a replacement.
 *
 * Evaluated AT BOOT rather than on a timer, which is a deliberate constraint
 * rather than a simplification. The credentials that let the enclave call KMS
 * are the parent's instance-role credentials and expire in roughly six hours,
 * so a long-running timer would have to solve credential refresh before it
 * could seal anything it renewed. At boot they are minutes old. With ~7
 * rotations a week against a 90-day certificate, a 30-day window offers dozens
 * of chances to renew -- so the timer would buy nothing and cost a moving part.
 *
 * Unparsable material returns true: if we cannot tell when it expires, ordering
 * is the safe direction.
 */
export function needsRenewal(payload, { now = Date.now(), renewBeforeMs = RENEW_BEFORE_MS } = {}) {
  const notAfter = Date.parse(payload?.notAfter);
  if (!Number.isFinite(notAfter)) return true;
  return notAfter - now < renewBeforeMs;
}

/**
 * Read the validity window off a PEM chain's leaf certificate.
 *
 * Recorded at seal time so `isUsable` never has to re-parse a certificate to
 * answer a question about freshness, and so a blob whose contents cannot be
 * parsed fails at seal time rather than on the boot that depends on it.
 */
export function leafValidity(certPem) {
  const cert = new crypto.X509Certificate(certPem);
  return { notBefore: new Date(cert.validFrom).toISOString(), notAfter: new Date(cert.validTo).toISOString() };
}

/** Outcomes of the boot-time round-trip check, reported on /health. */
export const SELF_TEST_VALUES = Object.freeze([
  // Sealed and unsealed a throwaway payload. The gated path works.
  'ok',
  // Not configured: no CMK id, or no credentials to call KMS with.
  'absent',
  // Attempted and failed. Suffixed with a reason from SELF_TEST_REASONS.
  'failed',
]);

/**
 * Why the round-trip failed, as a fixed vocabulary.
 *
 * A REASON, NOT A MESSAGE, and for the same argument errorReport.mjs makes: an
 * error string from an upstream can quote the request that produced it, so
 * forwarding one from this component would be a content leak wearing a
 * debugging hat. Nothing user-derived goes near these KMS calls, but the rule
 * is worth keeping uniform rather than argued case by case.
 *
 * It exists because `failed` alone was not actionable. The first production run
 * of this path reported `failed` and left no way to tell an allow-list problem
 * from a malformed invocation — and the enclave console is unreadable in
 * production, because reading it needs --debug-mode, which zeroes PCR0.
 */
export const SELF_TEST_REASONS = Object.freeze({
  /** KMS refused. Almost always this measurement missing from the CMK policy. */
  ACCESS_DENIED: 'access-denied',
  /** The binary is absent from the image, or not executable. */
  TOOL_MISSING: 'tool-missing',
  /** kmstool ran and exited non-zero for some other reason. */
  TOOL_ERROR: 'tool-error',
  /** kmstool succeeded but its output had no PLAINTEXT/CIPHERTEXT line. */
  BAD_OUTPUT: 'bad-output',
  /** A data key came back that was not 32 bytes. */
  BAD_KEY_LENGTH: 'bad-key-length',
  /** kmstool did not return within the timeout — usually the vsock KMS proxy. */
  TIMEOUT: 'timeout',
  /**
   * The AES-GCM tag did not verify on unseal.
   *
   * Distinct from ACCESS_DENIED on purpose: KMS released a data key, it just
   * was not the one this ciphertext was sealed with. On a real boot that means
   * the stored blob and the wrapped key have been separated — a corrupted or
   * substituted store, not a permissions problem.
   */
  UNSEAL_FAILED: 'unseal-failed',
  /** Sealing and unsealing both worked but produced different bytes. */
  ROUNDTRIP_MISMATCH: 'roundtrip-mismatch',
  /** kmstool got a 200 it could not parse. */
  BAD_RESPONSE: 'bad-response',
  /** Anything not classified above. */
  UNKNOWN: 'unknown',
});

/**
 * AWS error names we are willing to repeat verbatim.
 *
 * A FIXED VOCABULARY, not a substring of the message. kmstool swallows the KMS
 * error body -- on a failure it prints only `Got non-200 answer from KMS: <n>`
 * and a generic line -- so the useful signal is the status code plus, when the
 * aws-c logger happens to include it, the exception NAME. Matching against this
 * list keeps the enum discipline: nothing not on the list is ever echoed.
 */
const AWS_ERROR_NAMES = Object.freeze([
  'AccessDeniedException', 'ValidationException', 'NotFoundException',
  'InvalidCiphertextException', 'KMSInvalidStateException', 'IncorrectKeyException',
  'DisabledException', 'InvalidGrantTokenException', 'InvalidKeyUsageException',
  'LimitExceededException', 'ThrottlingException', 'KeyUnavailableException',
  'DependencyTimeoutException', 'UnsupportedOperationException',
]);

/** Map a thrown error onto the vocabulary above. Never returns the message. */
export function classifyFailure(err) {
  const m = String(err?.message || '');
  // A named AWS exception is the most specific thing we can honestly report.
  for (const name of AWS_ERROR_NAMES) {
    if (m.includes(name)) return `kms-${name}`;
  }
  // kmstool's own wording for a non-200. The CODE is the discriminator: 400
  // means the request was rejected as malformed, 403 means authorization.
  const status = m.match(/non-200 answer from KMS:\s*(\d{3})/i);
  if (status) return `kms-http-${status[1]}`;
  if (/Could not read response from KMS/i.test(m)) return SELF_TEST_REASONS.BAD_RESPONSE;
  if (/AccessDenied|not authorized|is not authorized/i.test(m)) return SELF_TEST_REASONS.ACCESS_DENIED;
  if (/ENOENT|not found|No such file/i.test(m)) return SELF_TEST_REASONS.TOOL_MISSING;
  if (/timed out/i.test(m)) return SELF_TEST_REASONS.TIMEOUT;
  if (/had no (PLAINTEXT|CIPHERTEXT) field/i.test(m)) return SELF_TEST_REASONS.BAD_OUTPUT;
  if (/expected a 32-byte data key/i.test(m)) return SELF_TEST_REASONS.BAD_KEY_LENGTH;
  if (/round-trip returned different bytes/i.test(m)) return SELF_TEST_REASONS.ROUNDTRIP_MISMATCH;
  // Node's GCM tag failure wording varies across versions; match both forms.
  if (/unable to authenticate|unsupported state|bad decrypt/i.test(m)) return SELF_TEST_REASONS.UNSEAL_FAILED;
  // Known SDK wording, in decreasing specificity. These are fixed literals from
  // aws-nitro-enclaves-sdk-c, not free text from a provider.
  if (/Could not generate data key/i.test(m)) return 'kms-sdk-genkey-failed';
  if (/Could not decrypt/i.test(m)) return 'kms-sdk-decrypt-failed';
  if (/assert|Assertion|abort/i.test(m)) return 'kms-sdk-assert';
  // Last resort: the exit code plus whether stderr carried anything at all.
  // 134 is SIGABRT (an assertion inside the SDK); a clean 1 with empty stderr
  // means it failed before printing anything, which rules out the HTTP path.
  const exited = m.match(/kmstool \w+ exited (\d+) stderr=(present|empty)/i);
  if (exited) return `tool-exit-${exited[1]}-${exited[2]}`;
  if (/kmstool \w+ exited/i.test(m)) return SELF_TEST_REASONS.TOOL_ERROR;
  return SELF_TEST_REASONS.UNKNOWN;
}

/**
 * Build KMS credentials from the environment, or null when unconfigured.
 *
 * Absent is a first-class answer, not an error: this ships inert, exactly as
 * in-enclave ACME did in v0.7.0. Without `ACME_STORE_KEY_ID` in the init blob
 * nothing here runs, so the image can be deployed and measured before anything
 * depends on it.
 */
export function storeCredsFromEnv(env = process.env) {
  const keyId = env.ACME_STORE_KEY_ID;
  const accessKeyId = env.KMS_AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.KMS_AWS_SECRET_ACCESS_KEY;
  if (!keyId || !accessKeyId || !secretAccessKey) return null;
  return {
    keyId,
    accessKeyId,
    secretAccessKey,
    sessionToken: env.KMS_AWS_SESSION_TOKEN || '',
    region: env.KMS_REGION || 'us-east-1',
    proxyPort: env.KMS_PORT || '8000',
  };
}

/**
 * Seal and unseal a throwaway payload at boot.
 *
 * WHY EVERY BOOT, AND WHY BEFORE ANYTHING NEEDS IT
 * ------------------------------------------------
 * Two reasons, and the first is the one that matters.
 *
 * A PCR0-bound resource that nothing exercises rots invisibly. The CMK's
 * allow-list sat naming two retired measurements while production ran a third,
 * and nothing noticed for months, because the cutover delivered plaintext and
 * so no code path ever attempted a gated call (#11, #84). The client
 * accept-list survived only because every rotation touches it and the drift
 * check fails when it is wrong. This is that treatment for the store: a
 * measurement that cannot decrypt now says so on /health at boot, not on the
 * distant morning a certificate needs renewing.
 *
 * Second, `genkey` is a code path that has never run in this system, and per
 * DEV-ENCLAVE.md it can only ever be exercised in production -- a dev enclave's
 * PCR0 cannot satisfy the production CMK. Proving it against a throwaway string
 * separates "sealing works" from "Let's Encrypt works", so a failure names
 * itself instead of surfacing as a mysterious ACME problem.
 *
 * Never throws: a failed self-test degrades the store, and must not take down
 * an enclave that is otherwise serving traffic.
 */
export async function selfTest({ kms, domain = 'self-test.invalid', log = () => {} } = {}) {
  if (!kms) return 'absent';
  try {
    const probe = { domain, cert: 'self-test', key: crypto.randomBytes(16).toString('hex') };
    const blob = await sealStore(probe, { kms, domain });
    const back = await unsealStore(blob, { kms });
    if (back.key !== probe.key) throw new Error('round-trip returned different bytes');
    log('acme-store: self-test ok (seal + attestation-gated unseal)');
    return 'ok';
  } catch (e) {
    // The message goes to the console (which only the enclave sees); the
    // classified reason is what reaches /health.
    const reason = classifyFailure(e);
    log(`acme-store: self-test FAILED (${reason}): ${e.message}`);
    return `failed:${reason}`;
  }
}

/**
 * Hand a sealed blob to the parent to persist.
 *
 * boot.sh bridges 127.0.0.1:STORE_PORT to the parent's vsock listener, which
 * writes the bytes to a file and renames it into place. The listener needs no
 * trust whatsoever: what it receives is already sealed, and a parent that
 * refused to store it, corrupted it, or handed back something else would only
 * cost us a fresh ACME order on the next boot.
 *
 * Resolves false rather than throwing. Failing to persist a certificate we have
 * already obtained must not stop us serving it.
 */
export function saveSealedBlob(blob, { port, host = '127.0.0.1', timeoutMs = 10_000, log = () => {} } = {}) {
  return new Promise((resolve) => {
    if (!port) {
      log('acme-store: no save channel configured; certificate not persisted');
      return resolve(false);
    }
    const socket = net.connect({ port: Number(port), host });
    let settled = false;
    const finish = (ok, why) => {
      if (settled) return;
      settled = true;
      if (!ok) log(`acme-store: save failed (${why}); certificate not persisted`);
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => finish(false, 'timeout'));
    socket.on('error', (e) => finish(false, e.message));
    // The parent sees end-of-stream as end-of-object, so the write must be
    // finished with end() rather than left open.
    socket.on('connect', () => socket.end(JSON.stringify(blob)));
    socket.on('close', () => finish(true));
  });
}

/**
 * Parse the sealed blob the parent supplied at boot, or null.
 *
 * Anything malformed is null, not a throw: a parent that hands over rubbish
 * should cost us one ACME order, not a boot failure.
 */
export function parseStoreBlob(raw, { log = () => {} } = {}) {
  if (!raw) return null;
  try {
    const blob = JSON.parse(raw);
    return blob && typeof blob === 'object' ? blob : null;
  } catch (e) {
    log(`acme-store: supplied blob is not JSON (${e.message}); ignoring`);
    return null;
  }
}

/**
 * Load and validate the cached certificate for `domain`.
 *
 * Returns { payload, servable, renew } so the caller can act on the two
 * questions independently -- see the note on `isServable`.
 */
export async function loadCachedCertificate({
  raw, kms, domain, domains, directoryUrl, now = Date.now(), log = () => {},
}) {
  const blob = parseStoreBlob(raw, { log });
  if (!blob || !kms) return { payload: null, servable: false, renew: true };
  let payload;
  try {
    payload = await unsealStore(blob, { kms });
  } catch (e) {
    // An AccessDenied here means this measurement is not on the CMK allow-list.
    log(`acme-store: could not unseal the cached certificate (${e.message})`);
    return { payload: null, servable: false, renew: true };
  }
  const servable = isServable(payload, { domain, domains, directoryUrl, now });
  const renew = !servable || needsRenewal(payload, { now });
  log(`acme-store: cached certificate servable=${servable} renew=${renew}`);
  return { payload: servable ? payload : null, servable, renew };
}
