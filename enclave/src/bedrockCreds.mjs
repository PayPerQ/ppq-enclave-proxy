/**
 * Bedrock signing credentials: in-memory holder + the loopback creds channel.
 *
 * Unlike the bearer keys (decrypted once by boot.sh and frozen into env), the
 * Bedrock credentials are SHORT-LIVED STS session creds (~1h) that the host
 * re-delivers on a timer over vsock:7001 (boot.sh forwards that port to the
 * loopback listener here — a running Node process cannot receive new env).
 * Node owns the swap: each blob replaces the whole triple atomically.
 *
 * Two delivery modes, mirroring the OpenRouter/Fireworks key pattern exactly:
 *   - KMS-enveloped (preferred): `bedrock_creds_ciphertext` is the KMS
 *     encryption of the creds JSON under the attestation-gated CMK; the blob
 *     also carries the parent's IMDS role creds, used ONLY as
 *     kmstool_enclave_cli arguments (exactly like boot.sh's key decrypt). KMS
 *     releases the plaintext only to an enclave whose PCR0 matches the key
 *     policy — the same trust anchor as the bearer keys.
 *   - Plaintext fields (documented fallback, not attestation-gated): the same
 *     posture the bearer keys ship with while kmstool integration lands.
 *
 * Failure posture: any bad/expired/missing blob leaves the previous value in
 * place (or null), which the connector reports as a skip — the request falls
 * through to OpenRouter. A malicious host can deny Bedrock, never break it.
 */
import net from 'node:net';
import { execFile } from 'node:child_process';

const MAX_BLOB_BYTES = 64 * 1024;

/** Run kmstool_enclave_cli decrypt (same invocation shape as boot.sh). */
function kmsDecrypt({ ciphertext, region, kmsPort, parentCreds }, cb) {
  const args = [
    'decrypt',
    '--region', region,
    '--proxy-port', String(kmsPort),
    '--aws-access-key-id', parentCreds.accessKeyId,
    '--aws-secret-access-key', parentCreds.secretAccessKey,
    '--aws-session-token', parentCreds.sessionToken,
    '--ciphertext', ciphertext,
  ];
  execFile('kmstool_enclave_cli', args, { timeout: 15_000 }, (err, stdout) => {
    if (err) return cb(err);
    const b64 = String(stdout).replace(/^PLAINTEXT:\s*/, '').trim();
    try {
      cb(null, Buffer.from(b64, 'base64').toString('utf8'));
    } catch (decodeErr) {
      cb(decodeErr);
    }
  });
}

function parseCredsJson(text) {
  const parsed = JSON.parse(text);
  return normalizeCreds({
    accessKeyId: parsed.access_key_id ?? parsed.accessKeyId ?? parsed.AccessKeyId,
    secretAccessKey: parsed.secret_access_key ?? parsed.secretAccessKey ?? parsed.SecretAccessKey,
    sessionToken: parsed.session_token ?? parsed.sessionToken ?? parsed.Token ?? parsed.SessionToken,
    expiration: parsed.expiration ?? parsed.Expiration,
  });
}

function normalizeCreds({ accessKeyId, secretAccessKey, sessionToken, expiration }) {
  if (typeof accessKeyId !== 'string' || accessKeyId === '') return null;
  if (typeof secretAccessKey !== 'string' || secretAccessKey === '') return null;
  const creds = { accessKeyId, secretAccessKey };
  if (typeof sessionToken === 'string' && sessionToken !== '') creds.sessionToken = sessionToken;
  if (typeof expiration === 'string' && expiration !== '') {
    const when = new Date(expiration);
    if (!Number.isNaN(when.getTime())) creds.expiration = when;
  }
  return creds;
}

export class BedrockCredsHolder {
  constructor({ kmsPort = 8000, log = () => {} } = {}) {
    this.kmsPort = kmsPort;
    this.log = log;
    this.creds = null;
  }

  /** Current creds, or null when none/expired (60s safety margin). */
  get(now = new Date()) {
    const creds = this.creds;
    if (!creds) return null;
    if (creds.expiration instanceof Date && creds.expiration.getTime() - now.getTime() < 60_000) {
      return null;
    }
    return creds;
  }

  /**
   * Apply one delivery blob (init-blob subset or a vsock:7001 message).
   * Resolves true when new creds were installed. Never throws.
   */
  applyBlob(blob) {
    return new Promise((resolve) => {
      try {
        const region = typeof blob?.region === 'string' && blob.region ? blob.region : 'us-east-1';
        const ciphertext = blob?.bedrock_creds_ciphertext;
        if (typeof ciphertext === 'string' && ciphertext !== '') {
          const parentCreds = {
            accessKeyId: blob.aws_access_key_id || '',
            secretAccessKey: blob.aws_secret_access_key || '',
            sessionToken: blob.aws_session_token || '',
          };
          kmsDecrypt(
            { ciphertext, region, kmsPort: this.kmsPort, parentCreds },
            (err, plaintext) => {
              if (err) {
                this.log(`bedrock creds KMS decrypt failed: ${err.message}`);
                return resolve(false);
              }
              try {
                const creds = parseCredsJson(plaintext);
                if (!creds) {
                  this.log('bedrock creds blob decrypted but malformed');
                  return resolve(false);
                }
                this.creds = creds;
                this.log(`bedrock creds installed (kms, expires=${creds.expiration?.toISOString() ?? 'unset'})`);
                resolve(true);
              } catch (parseErr) {
                this.log(`bedrock creds parse failed: ${parseErr.message}`);
                resolve(false);
              }
            },
          );
          return;
        }

        const creds = normalizeCreds({
          accessKeyId: blob?.bedrock_access_key_id,
          secretAccessKey: blob?.bedrock_secret_access_key,
          sessionToken: blob?.bedrock_session_token,
          expiration: blob?.bedrock_expiration,
        });
        if (!creds) return resolve(false);
        this.creds = creds;
        this.log(
          `bedrock creds installed (plaintext fallback, not attestation-gated, expires=${creds.expiration?.toISOString() ?? 'unset'})`,
        );
        resolve(true);
      } catch (err) {
        this.log(`bedrock creds blob rejected: ${err.message}`);
        resolve(false);
      }
    });
  }

  /**
   * Loopback listener for the host's refresh channel. boot.sh forwards
   * vsock:7001 here; one JSON blob per connection, connection close = EOF.
   */
  listen(port, host = '127.0.0.1') {
    const server = net.createServer((socket) => {
      const parts = [];
      let size = 0;
      socket.on('data', (data) => {
        size += data.length;
        if (size > MAX_BLOB_BYTES) {
          this.log('bedrock creds blob oversized; dropping connection');
          socket.destroy();
          return;
        }
        parts.push(data);
      });
      socket.on('end', () => {
        if (parts.length === 0) return;
        try {
          const blob = JSON.parse(Buffer.concat(parts).toString('utf8'));
          void this.applyBlob(blob);
        } catch (err) {
          this.log(`bedrock creds blob was not JSON: ${err.message}`);
        }
      });
      socket.on('error', () => {});
    });
    server.on('error', (err) => this.log(`bedrock creds listener error: ${err.message}`));
    server.listen(port, host);
    return server;
  }
}
