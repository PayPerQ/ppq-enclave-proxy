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
# Anthropic direct key — OPTIONAL. Same two delivery modes.
ANTH_CIPHERTEXT="${ANTHROPIC_KEY_CIPHERTEXT:-}"
ANTH_PLAINTEXT="${ANTHROPIC_KEY_PLAINTEXT:-}"
# Bedrock signing creds (Phase 2) — OPTIONAL first delivery so the enclave can
# serve Bedrock before the first send-creds.sh timer tick. Either a KMS
# ciphertext of the creds JSON (attestation-gated; scripts/send-creds.sh builds
# it) or the plaintext triple (fallback, not gated). Refreshes ride vsock:7001.
# BEDROCK_EXPIRATION is REQUIRED with the plaintext triple — the enclave
# rejects expiration-less creds rather than treating them as never-expiring.
BR_CIPHERTEXT="${BEDROCK_CREDS_CIPHERTEXT:-}"
BR_AKID="${BEDROCK_ACCESS_KEY_ID:-}"
BR_SECRET="${BEDROCK_SECRET_ACCESS_KEY:-}"
BR_TOKEN="${BEDROCK_SESSION_TOKEN:-}"
BR_EXPIRATION="${BEDROCK_EXPIRATION:-}"

AKID="" ; SECRET="" ; TOKEN=""
if [ -n "$CIPHERTEXT" ] || [ -n "$FW_CIPHERTEXT" ] || [ -n "$BR_CIPHERTEXT" ] || [ -n "$ANTH_CIPHERTEXT" ]; then
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

# Secrets ride the ENVIRONMENT into jq, never `--arg` — /proc/<pid>/cmdline is
# world-readable on Linux, so argument-passed keys would be exposed to any
# local process for the call's duration (CodeRabbit, PR #17).
BLOB=$(BL_REGION="$REGION" BL_SETTLE_HOST="$SETTLE_HOST" \
  BL_SETTLE_SECRET="$ENCLAVE_SETTLE_SECRET" \
  BL_SAFETY_SECRET="${SAFETY_IDENTIFIER_SECRET:-}" \
  BL_OR_CT="$CIPHERTEXT" BL_OR_PT="$PLAINTEXT" \
  BL_FW_CT="$FW_CIPHERTEXT" BL_FW_PT="$FW_PLAINTEXT" \
  BL_ANTH_CT="$ANTH_CIPHERTEXT" BL_ANTH_PT="$ANTH_PLAINTEXT" \
  BL_BR_CT="$BR_CIPHERTEXT" BL_BR_AKID="$BR_AKID" BL_BR_SECRET="$BR_SECRET" \
  BL_BR_TOKEN="$BR_TOKEN" BL_BR_EXP="$BR_EXPIRATION" \
  BL_AKID="$AKID" BL_SECRET="$SECRET" BL_TOKEN="$TOKEN" \
  jq -n '{region: env.BL_REGION, settle_host: env.BL_SETTLE_HOST,
    settle_secret: env.BL_SETTLE_SECRET, safety_secret: env.BL_SAFETY_SECRET,
    openrouter_key_ciphertext: env.BL_OR_CT, openrouter_key_plaintext: env.BL_OR_PT,
    fireworks_key_ciphertext: env.BL_FW_CT, fireworks_key_plaintext: env.BL_FW_PT,
    anthropic_key_ciphertext: env.BL_ANTH_CT, anthropic_key_plaintext: env.BL_ANTH_PT,
    bedrock_creds_ciphertext: env.BL_BR_CT, bedrock_access_key_id: env.BL_BR_AKID,
    bedrock_secret_access_key: env.BL_BR_SECRET, bedrock_session_token: env.BL_BR_TOKEN,
    bedrock_expiration: env.BL_BR_EXP,
    aws_access_key_id: env.BL_AKID, aws_secret_access_key: env.BL_SECRET,
    aws_session_token: env.BL_TOKEN}')

echo ">> sending init blob to vsock:${ENCLAVE_CID}:7000"
printf '%s' "$BLOB" | socat -u - VSOCK-CONNECT:${ENCLAVE_CID}:7000
echo ">> sent"
