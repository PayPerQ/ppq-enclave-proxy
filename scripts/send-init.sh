#!/usr/bin/env bash
# Send the one-shot init blob to a running enclave over vsock:7000.
#
# Two key-delivery modes:
#   KMS (attestation-gated, preferred):
#       OPENROUTER_KEY_CIPHERTEXT=<base64 KMS ciphertext> ./send-init.sh
#     The parent passes its IMDS role credentials + the ciphertext; the enclave
#     runs kmstool_enclave_cli, and KMS releases the key ONLY if the attestation
#     PCR0 matches the key policy. The parent never sees the plaintext key.
#   Plaintext (PoC fallback, NOT gated):
#       OPENROUTER_KEY_PLAINTEXT=sk-... ./send-init.sh
#
# Env: SETTLE_HOST, ENCLAVE_SETTLE_SECRET, REGION (default us-east-1),
#      ENCLAVE_CID (default 16)
#      SAFETY_IDENTIFIER_SECRET (optional) — must equal horse-power's value so
#        the OpenAI safety identifier (issue #657) matches the cleartext path;
#        if unset, the enclave simply omits the identifier (no-op).
set -euo pipefail

REGION="${REGION:-us-east-1}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
: "${SETTLE_HOST:?set SETTLE_HOST}"
: "${ENCLAVE_SETTLE_SECRET:?set ENCLAVE_SETTLE_SECRET}"

CIPHERTEXT="${OPENROUTER_KEY_CIPHERTEXT:-}"
PLAINTEXT="${OPENROUTER_KEY_PLAINTEXT:-}"
# Fireworks direct key (Phase 1b) — OPTIONAL. Same two delivery modes.
FW_CIPHERTEXT="${FIREWORKS_KEY_CIPHERTEXT:-}"
FW_PLAINTEXT="${FIREWORKS_KEY_PLAINTEXT:-}"
# Bedrock signing creds (Phase 2) — OPTIONAL first delivery so the enclave can
# serve Bedrock before the first send-creds.sh timer tick. Either a KMS
# ciphertext of the creds JSON (attestation-gated; scripts/send-creds.sh builds
# it) or the plaintext triple (fallback, not gated). Refreshes ride vsock:7001.
BR_CIPHERTEXT="${BEDROCK_CREDS_CIPHERTEXT:-}"
BR_AKID="${BEDROCK_ACCESS_KEY_ID:-}"
BR_SECRET="${BEDROCK_SECRET_ACCESS_KEY:-}"
BR_TOKEN="${BEDROCK_SESSION_TOKEN:-}"
BR_EXPIRATION="${BEDROCK_EXPIRATION:-}"

AKID="" ; SECRET="" ; TOKEN=""
if [ -n "$CIPHERTEXT" ] || [ -n "$FW_CIPHERTEXT" ] || [ -n "$BR_CIPHERTEXT" ]; then
  echo ">> fetching IMDS role credentials for in-enclave KMS decrypt"
  TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
  AKID=$(echo "$CREDS" | jq -r '.AccessKeyId')
  SECRET=$(echo "$CREDS" | jq -r '.SecretAccessKey')
  TOKEN=$(echo "$CREDS" | jq -r '.Token')
fi

BLOB=$(jq -n \
  --arg region "$REGION" \
  --arg settle_host "$SETTLE_HOST" \
  --arg settle_secret "$ENCLAVE_SETTLE_SECRET" \
  --arg safety_secret "${SAFETY_IDENTIFIER_SECRET:-}" \
  --arg ct "$CIPHERTEXT" \
  --arg pt "$PLAINTEXT" \
  --arg fw_ct "$FW_CIPHERTEXT" \
  --arg fw_pt "$FW_PLAINTEXT" \
  --arg br_ct "$BR_CIPHERTEXT" \
  --arg br_akid "$BR_AKID" --arg br_secret "$BR_SECRET" \
  --arg br_token "$BR_TOKEN" --arg br_exp "$BR_EXPIRATION" \
  --arg akid "$AKID" --arg secret "$SECRET" --arg token "$TOKEN" \
  '{region:$region, settle_host:$settle_host, settle_secret:$settle_secret,
    safety_secret:$safety_secret,
    openrouter_key_ciphertext:$ct, openrouter_key_plaintext:$pt,
    fireworks_key_ciphertext:$fw_ct, fireworks_key_plaintext:$fw_pt,
    bedrock_creds_ciphertext:$br_ct, bedrock_access_key_id:$br_akid,
    bedrock_secret_access_key:$br_secret, bedrock_session_token:$br_token,
    bedrock_expiration:$br_exp,
    aws_access_key_id:$akid, aws_secret_access_key:$secret, aws_session_token:$token}')

echo ">> sending init blob to vsock:${ENCLAVE_CID}:7000"
printf '%s' "$BLOB" | socat -u - VSOCK-CONNECT:${ENCLAVE_CID}:7000
echo ">> sent"
