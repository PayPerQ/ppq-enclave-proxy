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
set -euo pipefail

REGION="${REGION:-us-east-1}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
: "${SETTLE_HOST:?set SETTLE_HOST}"
: "${ENCLAVE_SETTLE_SECRET:?set ENCLAVE_SETTLE_SECRET}"

CIPHERTEXT="${OPENROUTER_KEY_CIPHERTEXT:-}"
PLAINTEXT="${OPENROUTER_KEY_PLAINTEXT:-}"

AKID="" ; SECRET="" ; TOKEN=""
if [ -n "$CIPHERTEXT" ]; then
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
  --arg ct "$CIPHERTEXT" \
  --arg pt "$PLAINTEXT" \
  --arg akid "$AKID" --arg secret "$SECRET" --arg token "$TOKEN" \
  '{region:$region, settle_host:$settle_host, settle_secret:$settle_secret,
    openrouter_key_ciphertext:$ct, openrouter_key_plaintext:$pt,
    aws_access_key_id:$akid, aws_secret_access_key:$secret, aws_session_token:$token}')

echo ">> sending init blob to vsock:${ENCLAVE_CID}:7000"
printf '%s' "$BLOB" | socat -u - VSOCK-CONNECT:${ENCLAVE_CID}:7000
echo ">> sent"
