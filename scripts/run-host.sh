#!/usr/bin/env bash
# Start the host-side plumbing for the PPQ enclave proxy, then run the enclave.
#
# The parent instance is deliberately "dumb": it forwards ciphertext only.
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
  - {address: ${SETTLE_HOST}, port: 443}
  - {address: kms.${REGION}.amazonaws.com, port: 443}
EOF

echo ">> starting outbound vsock-proxies"
pkill -f 'vsock-proxy' 2>/dev/null || true
vsock-proxy 9443 openrouter.ai 443 --config /etc/nitro_enclaves/ppq-vsock-proxy.yaml &
vsock-proxy 9444 "${SETTLE_HOST}" 443 --config /etc/nitro_enclaves/ppq-vsock-proxy.yaml &
vsock-proxy 8000 "kms.${REGION}.amazonaws.com" 443 --config /etc/nitro_enclaves/ppq-vsock-proxy.yaml &

echo ">> starting inbound forwarder (public :8443 -> enclave vsock:8443)"
pkill -f 'TCP4-LISTEN:8443' 2>/dev/null || true
socat TCP4-LISTEN:8443,reuseaddr,fork VSOCK-CONNECT:${ENCLAVE_CID}:8443 &

echo ">> terminating any running enclave"
nitro-cli terminate-enclave --all 2>/dev/null || true

echo ">> running enclave (cid=${ENCLAVE_CID})"
nitro-cli run-enclave \
  --eif-path "$EIF" \
  --cpu-count 2 \
  --memory 3072 \
  --enclave-cid "${ENCLAVE_CID}" \
  --debug-mode

echo ">> enclave running. send init blob with scripts/send-init.sh"
