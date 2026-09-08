#!/usr/bin/env bash
# Start the host-side plumbing for the PPQ enclave proxy, then run the enclave.
#
# The plumbing THIS script starts is deliberately "dumb" — raw byte forwarding,
# no TLS termination. Note that is NOT the whole parent: the public browser path
# (enclave.ppq.ai:443) is served by nginx, which holds the Let's Encrypt key and
# DOES terminate the client's TLS before handing bytes to the :8443 forwarder
# below. On that path host-blindness comes from the EHBP seal, not from this
# script. See "Architecture" in the README.
#   - Inbound  : socat TCP:8443            -> vsock:8443  (raw client TLS bytes)
#   - OpenRouter: vsock-proxy vsock:9443   -> openrouter.ai:443
#   - Settle    : vsock-proxy vsock:9444   -> $SETTLE_HOST:443
#   - KMS       : vsock-proxy vsock:8000   -> kms.$REGION.amazonaws.com:443
#
# Env:
#   SETTLE_HOST   horse-power hostname the enclave settles against (e.g. ngrok host)
#   REGION        AWS region for the KMS vsock-proxy (default us-east-1)
set -euo pipefail

REGION="${REGION:-us-east-1}"
: "${SETTLE_HOST:?set SETTLE_HOST to the horse-power host (e.g. xxxx.ngrok-free.dev)}"

EIF="${EIF:-$(cd "$(dirname "$0")/.." && pwd)/build/ppq-enclave-proxy.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"

echo ">> writing vsock-proxy allowlist"
sudo tee /etc/nitro_enclaves/ppq-vsock-proxy.yaml >/dev/null <<EOF
allowlist:
  - {address: openrouter.ai, port: 443}
  - {address: api.fireworks.ai, port: 443}
  - {address: bedrock-mantle.us-east-2.api.aws, port: 443}
  - {address: bedrock-mantle.us-east-1.api.aws, port: 443}
  - {address: api.anthropic.com, port: 443}
  - {address: aiplatform.googleapis.com, port: 443}
  - {address: oauth2.googleapis.com, port: 443}
  - {address: ${SETTLE_HOST}, port: 443}
  - {address: acme-staging-v02.api.letsencrypt.org, port: 443}
  - {address: acme-v02.api.letsencrypt.org, port: 443}
  - {address: kms.${REGION}.amazonaws.com, port: 443}
EOF

echo ">> starting outbound vsock-proxies"
# --num_workers caps SIMULTANEOUS connections the proxy will forward. The CLI
# default is tiny (a handful), which silently serializes concurrent chat
# requests through the OpenRouter/settle tunnels — measured as a 15x throughput
# cliff under load. Set it high; each idle worker is just a cheap thread.
VSOCK_WORKERS="${VSOCK_WORKERS:-1024}"
CONF=/etc/nitro_enclaves/ppq-vsock-proxy.yaml
pkill -f 'vsock-proxy' 2>/dev/null || true
# setsid + detached I/O so the tunnels survive this shell's session ending —
# critical when run-host.sh is invoked over SSM RunShellScript, which kills the
# command's process group on completion and would otherwise take the plumbing
# down with it (the enclave VM survives; its shell-child tunnels would not).
setsid sh -c "exec vsock-proxy 9443 openrouter.ai 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9445 api.fireworks.ai 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
# Bedrock direct: one proxy per REGIONAL host (a vsock-proxy pins a single
# destination). Ports must match boot.sh's BEDROCK_*_VSOCK_PORT constants.
# bedrock-mantle is the OpenAI-Responses endpoint — the ONLY surface serving
# the OpenAI frontier models (live-probed; bedrock-runtime rejects them).
setsid sh -c "exec vsock-proxy 9446 bedrock-mantle.us-east-2.api.aws 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9447 bedrock-mantle.us-east-1.api.aws 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9448 api.anthropic.com 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
# Vertex direct (Phase 5): inference + Google's OAuth token endpoint (the
# enclave mints its own access tokens from the provisioned SA key). Ports
# must match boot.sh's VERTEX_VSOCK_PORT / GOOGLE_OAUTH_VSOCK_PORT.
setsid sh -c "exec vsock-proxy 9449 aiplatform.googleapis.com 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9450 oauth2.googleapis.com 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9444 ${SETTLE_HOST} 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9451 acme-staging-v02.api.letsencrypt.org 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 9452 acme-v02.api.letsencrypt.org 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &
setsid sh -c "exec vsock-proxy 8000 kms.${REGION}.amazonaws.com 443 --num_workers ${VSOCK_WORKERS} --config ${CONF}" </dev/null >/dev/null 2>&1 &

# --- Sealed certificate store (#83) ------------------------------------------
# The enclave has no disk, so an ACME-issued certificate would die with every
# restart and the next boot would spend one of Let's Encrypt's five weekly
# duplicates. The enclave seals the certificate under the attestation-gated CMK
# and hands it here; this listener only writes bytes to a file.
#
# IT CANNOT READ WHAT IT STORES, and that is the point: the parent holding a
# readable TLS private key could terminate TLS and impersonate the enclave,
# which is the property the in-enclave TLS work exists to establish. The file is
# ciphertext plus a wrapped data key. Deleting it is safe; it costs one order.
#
# Written to a temp name and renamed so a boot that races a save never reads a
# half-written file.
STORE_PORT="${STORE_PORT:-7002}"
STORE_PATH="${STORE_PATH:-/var/lib/ppq-enclave/acme-store.json}"
mkdir -p "$(dirname "$STORE_PATH")"
pkill -f "VSOCK-LISTEN:${STORE_PORT}" 2>/dev/null || true
setsid sh -c "exec socat VSOCK-LISTEN:${STORE_PORT},reuseaddr,fork \
  SYSTEM:'cat > ${STORE_PATH}.tmp && mv -f ${STORE_PATH}.tmp ${STORE_PATH}'" \
  </dev/null >/dev/null 2>&1 &
echo ">> sealed-store listener on vsock:${STORE_PORT} -> ${STORE_PATH}"

# INBOUND_LISTEN_PORT lets the DEV host put this forwarder straight on :443,
# where production keeps it on :8443 behind nginx. That is not a shortcut: it is
# the phase-3 end state of #52 (no L7 proxy in the byte path), so dev exercises
# the topology production is moving toward, and it is what makes ACME
# TLS-ALPN-01 reachable without an nginx SNI split. Same script, different env.
INBOUND_LISTEN_PORT="${INBOUND_LISTEN_PORT:-8443}"
echo ">> starting inbound forwarder (public :${INBOUND_LISTEN_PORT} -> enclave vsock:8443)"
pkill -f "TCP4-LISTEN:${INBOUND_LISTEN_PORT}" 2>/dev/null || true
setsid sh -c "exec socat TCP4-LISTEN:${INBOUND_LISTEN_PORT},reuseaddr,fork VSOCK-CONNECT:${ENCLAVE_CID}:8443" </dev/null >/dev/null 2>&1 &

echo ">> terminating any running enclave"
nitro-cli terminate-enclave --all 2>/dev/null || true

echo ">> running enclave (cid=${ENCLAVE_CID})"
# DO NOT add --debug-mode: AWS zeroes PCR0/1/2 in debug mode, so the enclave
# would attest all-zero measurements and every pinned client would REJECT it
# (clients verify the attested PCR0 against the reproducible-build value).
# Production runs WITHOUT it — that's what yields the real d08345a2… PCR0.
# ENCLAVE_CPUS / ENCLAVE_MEMORY_MIB size the enclave (#52 scaling). Both must
# fit /etc/nitro_enclaves/allocator.yaml on this host, and Nitro allocates
# whole cores: on an SMT instance cpu_count must be even and CPU 0's core
# stays with the parent.
ENCLAVE_CPUS="${ENCLAVE_CPUS:-2}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-3072}"
echo ">> enclave size: ${ENCLAVE_CPUS} vCPU, ${ENCLAVE_MEMORY_MIB} MiB"
nitro-cli run-enclave \
  --eif-path "$EIF" \
  --cpu-count "${ENCLAVE_CPUS}" \
  --memory "${ENCLAVE_MEMORY_MIB}" \
  --enclave-cid "${ENCLAVE_CID}"

echo ">> enclave running. send init blob with scripts/send-init.sh"
