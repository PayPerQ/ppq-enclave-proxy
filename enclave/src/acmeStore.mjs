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
        reject(new Error(`kmstool ${args[0]} exited ${code}: ${err.trim()}`));
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

function credentialArgs({ region, proxyPort, accessKeyId, secretAccessKey, sessionToken }) {
  const args = [
    '--region', region,
    '--proxy-port', String(proxyPort),
    '--aws-access-key-id', accessKeyId,
    '--aws-secret-access-key', secretAccessKey,
  ];
  // Instance-role credentials always carry a session token; a long-lived user
  // key would not. Omit rather than pass empty, which kmstool rejects.
  if (sessionToken) args.push('--aws-session-token', sessionToken);
  return args;
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
      const out = await runKmstool([
        'genkey', ...credentialArgs(creds),
        '--key-id', creds.keyId,
        '--key-spec', 'AES-256',
      ]);
      return {
        plaintextB64: parseKmstoolField(out, 'PLAINTEXT'),
        ciphertextB64: parseKmstoolField(out, 'CIPHERTEXT'),
      };
    },
    async decryptDataKey(ciphertextB64) {
      const out = await runKmstool([
        'decrypt', ...credentialArgs(creds),
        '--key-id', creds.keyId,
        '--ciphertext', ciphertextB64,
      ]);
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

/**
 * Whether unsealed material is fit to serve.
 *
 * This is the bound on the replay risk described at the top of the file: the
 * parent may re-present an older blob, so age is checked here rather than
 * trusted. `minRemainingMs` deliberately defaults to a value larger than a
 * renewal window is long, so a certificate that is about to lapse is treated as
 * unusable and triggers a fresh order while there is still time to get one.
 */
export function isUsable(payload, { domain, now = Date.now(), minRemainingMs = 24 * 3600_000 } = {}) {
  if (!payload || typeof payload !== 'object') return false;
  if (typeof payload.cert !== 'string' || !payload.cert) return false;
  if (typeof payload.key !== 'string' || !payload.key) return false;
  if (domain && payload.domain !== domain) return false;
  const notAfter = Date.parse(payload.notAfter);
  if (!Number.isFinite(notAfter)) return false;
  return notAfter - now > minRemainingMs;
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
  // Attempted and failed. The store cannot be trusted this boot.
  'failed',
]);

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
    // The message is ours or KMS's -- an AccessDenied here is the allow-list
    // being wrong, which is exactly what this exists to surface.
    log(`acme-store: self-test FAILED: ${e.message}`);
    return 'failed';
  }
}
