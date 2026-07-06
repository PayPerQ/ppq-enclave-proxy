#!/bin/sh
# PPQ Enclave Proxy — in-enclave entrypoint (PID 1 inside the Nitro Enclave).
#
# Responsibilities, in order:
#   1. Bring up loopback.
#   2. Open the in-enclave ends of the vsock tunnels (inbound + outbound).
#   3. Receive a one-shot init blob from the parent over vsock (config + either
#      the OpenRouter key ciphertext for in-enclave KMS decrypt, or, for the PoC
#      fallback, the key itself).
#   4. Obtain the OpenRouter API key:
#        - preferred: kmstool_enclave_cli Decrypt (KMS releases the key ONLY to
#          an attestation doc whose PCR0 matches the published image).
#        - fallback: key delivered in the init blob (documented, non-gated).
#   5. Generate an ephemeral self-signed TLS cert (terminates client TLS here).
#   6. exec the Node proxy.
#
# HOST_CID is always 3 for the parent instance.
set -eu

HOST_CID=3
INBOUND_VSOCK_PORT=8443
OR_VSOCK_PORT=9443
SETTLE_VSOCK_PORT=9444
KMS_VSOCK_PORT=8000
INIT_VSOCK_PORT=7000

log() { echo "{\"t\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"boot\":\"$*\"}"; }

log "bringing up loopback"
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up 2>/dev/null || true

# --- Outbound tunnels: in-enclave TCP listener -> host vsock -> real dest ------
# OpenRouter: connect to 127.0.0.1:9443 in-enclave -> host vsock-proxy -> openrouter.ai:443
socat TCP4-LISTEN:${OR_VSOCK_PORT},reuseaddr,fork,bind=127.0.0.1 \
      VSOCK-CONNECT:${HOST_CID}:${OR_VSOCK_PORT} &
# Settlement: 127.0.0.1:9444 -> host vsock-proxy -> <horse-power host>:443
socat TCP4-LISTEN:${SETTLE_VSOCK_PORT},reuseaddr,fork,bind=127.0.0.1 \
      VSOCK-CONNECT:${HOST_CID}:${SETTLE_VSOCK_PORT} &
# KMS: 127.0.0.1:8000 -> host vsock-proxy -> kms.<region>.amazonaws.com:443
socat TCP4-LISTEN:${KMS_VSOCK_PORT},reuseaddr,fork,bind=127.0.0.1 \
      VSOCK-CONNECT:${HOST_CID}:${KMS_VSOCK_PORT} &

# --- Receive init blob from parent (one-shot) ---------------------------------
log "waiting for init blob on vsock:${INIT_VSOCK_PORT}"
socat -u VSOCK-LISTEN:${INIT_VSOCK_PORT} OPEN:/tmp/init.json,creat,trunc
log "init blob received"

REGION=$(jq -r '.region // "us-east-1"' /tmp/init.json)
SETTLE_HOST=$(jq -r '.settle_host // ""' /tmp/init.json)
ENCLAVE_SETTLE_SECRET=$(jq -r '.settle_secret // ""' /tmp/init.json)
KEY_CIPHERTEXT=$(jq -r '.openrouter_key_ciphertext // ""' /tmp/init.json)
KEY_PLAINTEXT=$(jq -r '.openrouter_key_plaintext // ""' /tmp/init.json)
AWS_ACCESS_KEY_ID=$(jq -r '.aws_access_key_id // ""' /tmp/init.json)
AWS_SECRET_ACCESS_KEY=$(jq -r '.aws_secret_access_key // ""' /tmp/init.json)
AWS_SESSION_TOKEN=$(jq -r '.aws_session_token // ""' /tmp/init.json)

OPENROUTER_API_KEY=""
if [ -n "$KEY_CIPHERTEXT" ] && command -v kmstool_enclave_cli >/dev/null 2>&1; then
  log "decrypting OpenRouter key via attestation-gated KMS"
  OPENROUTER_API_KEY=$(kmstool_enclave_cli decrypt \
      --region "$REGION" \
      --proxy-port ${KMS_VSOCK_PORT} \
      --aws-access-key-id "$AWS_ACCESS_KEY_ID" \
      --aws-secret-access-key "$AWS_SECRET_ACCESS_KEY" \
      --aws-session-token "$AWS_SESSION_TOKEN" \
      --ciphertext "$KEY_CIPHERTEXT" 2>/tmp/kms.err \
      | sed 's/^PLAINTEXT: //' | base64 -d) \
    || { log "KMS decrypt FAILED: $(cat /tmp/kms.err)"; OPENROUTER_API_KEY=""; }
fi
if [ -z "$OPENROUTER_API_KEY" ] && [ -n "$KEY_PLAINTEXT" ]; then
  log "using init-channel OpenRouter key (fallback, not attestation-gated)"
  OPENROUTER_API_KEY="$KEY_PLAINTEXT"
fi
rm -f /tmp/init.json

# --- Ephemeral TLS cert (client TLS terminates inside the enclave) ------------
mkdir -p /app/tls
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /app/tls/key.pem -out /app/tls/cert.pem \
  -days 365 -subj "/CN=ppq-enclave-proxy" >/dev/null 2>&1
log "generated ephemeral TLS cert"

export OPENROUTER_API_KEY SETTLE_HOST ENCLAVE_SETTLE_SECRET
export INBOUND_PORT=${INBOUND_VSOCK_PORT}
export OR_PORT=${OR_VSOCK_PORT}
export SETTLE_PORT=${SETTLE_VSOCK_PORT}

# --- Inbound tunnel: host vsock -> in-enclave TLS server ----------------------
# The parent forwards raw client TCP (incl. TLS handshake) to vsock:8443; hand it
# to the Node HTTPS server on 127.0.0.1:8443.
socat VSOCK-LISTEN:${INBOUND_VSOCK_PORT},reuseaddr,fork \
      TCP4-CONNECT:127.0.0.1:${INBOUND_VSOCK_PORT} &

log "starting node proxy (key_loaded=$([ -n "$OPENROUTER_API_KEY" ] && echo yes || echo no))"
exec node /app/src/server.mjs
