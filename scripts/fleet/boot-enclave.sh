#!/usr/bin/env bash
# Boot the enclave on this host with no operator and no CI (#52 scaling, step 3).
#
# This is the cutover workflow's "Swap the running enclave", "Send the init
# blob" and "Deliver Bedrock signing credentials" steps, run by the box itself
# under its instance role, so that a machine started from the AMI -- by an
# autoscaling group, by a reboot, by a replacement -- comes up serving without
# anyone doing anything. Installed as the systemd oneshot ppq-enclave.service.
#
# Inputs, none of them baked into the image:
#   SSM /ppq-enclave/fleet-config  sizing + ACME settings (plain JSON, not secret)
#   SSM /ppq-enclave/*             provider keys (SecureString) + KMS ciphertexts
#   S3  ppq-enclave-sealed-store   the sealed certificate + EHBP identity blob
#
# The EIF is the one the AMI was baked with; a new measurement reaches a fleet
# box through a new AMI (instance refresh), never by rebuilding on the box.
set -euo pipefail
REGION="${REGION:-us-east-1}"
log() { echo "[boot-enclave] $*"; logger -t boot-enclave "$*"; }

CFG=$(aws ssm get-parameter --name /ppq-enclave/fleet-config --region "$REGION" --query Parameter.Value --output text)
cfg() { printf '%s' "$CFG" | jq -r --arg k "$1" '.[$k] // empty'; }
CHECKOUT="$(cfg checkout)"; CHECKOUT="${CHECKOUT:-/home/ec2-user/ppq-enclave-proxy}"
EIF="${EIF:-$CHECKOUT/build/ppq-enclave-proxy.eif}"
[ -s "$EIF" ] || { log "no EIF at $EIF"; exit 1; }
ENCLAVE_CID="$(cfg enclave_cid)"; ENCLAVE_CID="${ENCLAVE_CID:-16}"

# The allocator pool must fit what fleet-config asks for. It is baked into the
# AMI; asserting here turns a mismatch into a clear log line, not a run-enclave
# error twenty lines later.
POOL_CPUS=$(awk '/^cpu_count:/{print $2}' /etc/nitro_enclaves/allocator.yaml)
POOL_MEM=$(awk '/^memory_mib:/{print $2}' /etc/nitro_enclaves/allocator.yaml)
[ "${POOL_CPUS:-0}" -ge "$(cfg cpus)" ] && [ "${POOL_MEM:-0}" -ge "$(cfg memory_mib)" ] \
  || { log "allocator pool ${POOL_CPUS}vCPU/${POOL_MEM}MiB < fleet-config $(cfg cpus)/$(cfg memory_mib)"; exit 1; }

log "starting enclave: $(cfg cpus) vCPU, $(cfg memory_mib) MiB, workers=$(cfg workers)"
cd "$CHECKOUT"
# run-host.sh occasionally dies on a socat race before the enclave is up; the
# cutover retries once, so do the same.
for attempt in 1 2; do
  if HOME=/root NITRO_CLI_ARTIFACTS=/home/ec2-user/nitro-artifacts \
     ENCLAVE_CPUS="$(cfg cpus)" ENCLAVE_MEMORY_MIB="$(cfg memory_mib)" \
     SETTLE_HOST="$(cfg settle_host)" REGION="$REGION" ENCLAVE_CID="$ENCLAVE_CID" EIF="$EIF" \
     bash scripts/run-host.sh; then break; fi
  log "run-host.sh failed (attempt $attempt)"; sleep 5
done
for i in $(seq 1 30); do
  nitro-cli describe-enclaves | grep -q '"State": "RUNNING"' && break; sleep 2
done
nitro-cli describe-enclaves | grep -q '"State": "RUNNING"' || { log "enclave did not reach RUNNING"; exit 1; }

p() { aws ssm get-parameter --name "/ppq-enclave/$1" --with-decryption --region "$REGION" --query Parameter.Value --output text; }
log "sending init blob"
export OPENROUTER_KEY_CIPHERTEXT="$(p openrouter-key-ciphertext)" OPENROUTER_KEY_PLAINTEXT="$(p openrouter-key)" \
  VERTEX_SA_KEY_CIPHERTEXT="$(p vertex-sa-key-ciphertext)" VERTEX_SA_KEY_PLAINTEXT="$(p vertex-sa-key)" \
  ANTHROPIC_KEY_CIPHERTEXT="$(p anthropic-key-ciphertext)" ANTHROPIC_KEY_PLAINTEXT="$(p anthropic-key)" \
  FIREWORKS_KEY_CIPHERTEXT="$(p fireworks-key-ciphertext)" FIREWORKS_KEY_PLAINTEXT="$(p fireworks-key)" \
  ENCLAVE_SETTLE_SECRET="$(p settle-secret)" SAFETY_IDENTIFIER_SECRET="$(p safety-identifier)" \
  ACME_STORE_KEY_ID="$(cfg acme_store_key_id)" ACME_DOMAIN="$(cfg acme_domain)" ACME_DIRECTORY="$(cfg acme_directory)" \
  ENCLAVE_WORKERS="$(cfg workers)" SETTLE_HOST="$(cfg settle_host)" REGION="$REGION" ENCLAVE_CID="$ENCLAVE_CID" \
  ACME_RENEWAL_MODE="$(cfg acme_renewal_mode)" ACME_RENEWAL_AUTHORITY="$(cfg acme_renewal_authority)" \
  ACME_CI_TOKEN="$(p acme-ci-token 2>/dev/null || true)"
bash scripts/send-init.sh

# The creds listener only exists once server.mjs has finished its boot-time
# KMS work; a push before that is silently lost until the timer's next tick
# (20 min of Bedrock falling back to OpenRouter). So: healthy FIRST, then
# deliver.
healthy=0
for i in $(seq 1 45); do
  curl -sk --max-time 5 https://127.0.0.1:8443/health | grep -q '"status":"ok"' && { healthy=1; break; }
  sleep 2
done
[ "$healthy" = 1 ] || { log "enclave started but /health did not answer within 90s"; exit 1; }
log "enclave healthy"

log "installing the Bedrock credential refresh timer"
install -m 644 scripts/systemd/ppq-bedrock-creds.service scripts/systemd/ppq-bedrock-creds.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ppq-bedrock-creds.timer
systemctl start ppq-bedrock-creds.service || log "first creds delivery failed; the timer retries"
for i in $(seq 1 10); do
  curl -sk --max-time 5 https://127.0.0.1:8443/health | grep -q '"bedrockCredsLoaded":true' && { log "bedrock creds loaded"; exit 0; }
  sleep 2
done
log "bedrock creds not confirmed within 20s; the timer retries (Bedrock falls back to OpenRouter meanwhile)"
exit 0
