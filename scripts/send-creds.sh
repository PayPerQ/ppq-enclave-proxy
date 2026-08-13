#!/usr/bin/env bash
# Refresh the enclave's Bedrock signing credentials over vsock:7001.
#
# Run on a timer (~every 30 min — STS session creds live ~1h and the enclave
# refuses to sign within 60s of expiry). The enclave applies each blob
# atomically; a missed tick degrades to the OpenRouter fallback, never an error.
#
# Credential source: a dedicated invoke-only role. The host assumes it so the
# creds delivered to the enclave carry ONLY bedrock:InvokeModel* on the four
# model ARNs — never the parent instance's full role.
#
# Two delivery modes, exactly like send-init.sh's key delivery:
#   KMS-enveloped (attestation-gated, preferred):
#       BEDROCK_KMS_KEY_ID=<arn> ./send-creds.sh
#     The creds JSON is KMS-encrypted under the attestation-gated CMK; the
#     enclave decrypts with kmstool, so KMS releases them ONLY to a PCR0 that
#     matches the key policy. The blob also carries the parent's IMDS creds as
#     kmstool arguments (same pattern as the boot-time key decrypt).
#   Plaintext (fallback, NOT gated):
#       ./send-creds.sh    # without BEDROCK_KMS_KEY_ID
#
# Env: BEDROCK_ROLE_ARN (default: the ppq-enclave-bedrock-invoke role),
#      BEDROCK_KMS_KEY_ID (optional — enables the KMS mode),
#      REGION (default us-east-1, the KMS region), ENCLAVE_CID (default 16)
#
# Systemd timer example (install as ppq-bedrock-creds.{service,timer}):
#   [Service] Type=oneshot
#   ExecStart=/home/ec2-user/ppq-enclave-proxy/scripts/send-creds.sh
#   [Timer] OnBootSec=2min
#   OnUnitActiveSec=30min
#   [Install] WantedBy=timers.target
set -euo pipefail

REGION="${REGION:-us-east-1}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ROLE_ARN="${BEDROCK_ROLE_ARN:-arn:aws:iam::287432920037:role/ppq-enclave-bedrock-invoke}"
KMS_KEY_ID="${BEDROCK_KMS_KEY_ID:-}"

echo ">> assuming ${ROLE_ARN}"
ASSUMED=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "ppq-enclave-bedrock-$(date +%s)" \
  --duration-seconds 3600 \
  --output json)
CREDS_JSON=$(echo "$ASSUMED" | jq -c '{
  access_key_id: .Credentials.AccessKeyId,
  secret_access_key: .Credentials.SecretAccessKey,
  session_token: .Credentials.SessionToken,
  expiration: .Credentials.Expiration}')

if [ -n "$KMS_KEY_ID" ]; then
  echo ">> KMS-encrypting creds under ${KMS_KEY_ID} (attestation-gated release)"
  # AWS CLI v2 takes binary params base64-encoded by default.
  CIPHERTEXT=$(aws kms encrypt \
    --region "$REGION" \
    --key-id "$KMS_KEY_ID" \
    --plaintext "$(printf '%s' "$CREDS_JSON" | base64 -w0 2>/dev/null || printf '%s' "$CREDS_JSON" | base64)" \
    --query CiphertextBlob --output text)

  echo ">> fetching IMDS role credentials (kmstool arguments inside the enclave)"
  TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  IMDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")

  BLOB=$(jq -n \
    --arg region "$REGION" \
    --arg ct "$CIPHERTEXT" \
    --arg akid "$(echo "$IMDS" | jq -r '.AccessKeyId')" \
    --arg secret "$(echo "$IMDS" | jq -r '.SecretAccessKey')" \
    --arg token "$(echo "$IMDS" | jq -r '.Token')" \
    '{region:$region, bedrock_creds_ciphertext:$ct,
      aws_access_key_id:$akid, aws_secret_access_key:$secret, aws_session_token:$token}')
else
  echo ">> WARNING: plaintext delivery (not attestation-gated) — set BEDROCK_KMS_KEY_ID for the gated mode"
  BLOB=$(echo "$CREDS_JSON" | jq -c '{
    bedrock_access_key_id: .access_key_id,
    bedrock_secret_access_key: .secret_access_key,
    bedrock_session_token: .session_token,
    bedrock_expiration: .expiration}')
fi

echo ">> sending creds blob to vsock:${ENCLAVE_CID}:7001"
printf '%s' "$BLOB" | socat -u - VSOCK-CONNECT:${ENCLAVE_CID}:7001
echo ">> sent"
