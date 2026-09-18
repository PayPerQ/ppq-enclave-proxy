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
#   - Inbound PP: socat unix:$INBOUND_PP_SOCKET -> vsock:8445
#                 (PROXY header + raw TLS bytes; api path; off by default;
#                 the path must be /run/ppq/<name>)
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
  - {address: bedrock-mantle.us-west-2.api.aws, port: 443}
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
# cliff under load. Set it high on the request path.
#
# But vsock-proxy spawns every worker THREAD at startup, and the processes land in
# the cgroup of whatever started this script (ppq-enclave.service on a fleet box,
# amazon-ssm-agent.service over SSM), whose systemd TasksMax defaults to 15% of
# threads-max: 18,761 on c6i.2xlarge, 9,248 on c6i.xlarge. Twelve proxies at 1024
# need ~12,300. Past the limit, thread creation fails with EAGAIN and
# vsock-proxy PANICS, and which tunnels die is random (#173). The control-plane
# tunnels (KMS, Google OAuth, ACME) carry a handful of calls a day, so they get
# CONTROL_WORKERS, which also keeps a smaller host under its limit.
VSOCK_WORKERS="${VSOCK_WORKERS:-1024}"
CONTROL_WORKERS="${CONTROL_WORKERS:-64}"
CONF=/etc/nitro_enclaves/ppq-vsock-proxy.yaml
# "vsock-port host workers". Ports must match boot.sh's *_VSOCK_PORT constants.
PROXIES=(
  "9443 openrouter.ai ${VSOCK_WORKERS}"
  "9445 api.fireworks.ai ${VSOCK_WORKERS}"
  # Bedrock direct: one proxy per REGIONAL host (a vsock-proxy pins a single
  # destination). bedrock-mantle is the OpenAI-Responses endpoint — the ONLY
  # surface serving the OpenAI frontier models (live-probed; bedrock-runtime
  # rejects them). us-west-2 is the only mantle region that serves GPT-6 Astra
  # (2026-09-10); port 9453 = boot.sh BEDROCK_USW2_VSOCK_PORT.
  "9446 bedrock-mantle.us-east-2.api.aws ${VSOCK_WORKERS}"
  "9447 bedrock-mantle.us-east-1.api.aws ${VSOCK_WORKERS}"
  "9453 bedrock-mantle.us-west-2.api.aws ${VSOCK_WORKERS}"
  "9448 api.anthropic.com ${VSOCK_WORKERS}"
  # Vertex direct (Phase 5): inference, plus Google's OAuth token endpoint (the
  # enclave mints its own access tokens from the provisioned SA key).
  "9449 aiplatform.googleapis.com ${VSOCK_WORKERS}"
  "9450 oauth2.googleapis.com ${CONTROL_WORKERS}"
  "9444 ${SETTLE_HOST} ${VSOCK_WORKERS}"
  "9451 acme-staging-v02.api.letsencrypt.org ${CONTROL_WORKERS}"
  "9452 acme-v02.api.letsencrypt.org ${CONTROL_WORKERS}"
  "8000 kms.${REGION}.amazonaws.com ${CONTROL_WORKERS}"
)
# setsid + detached I/O so the tunnels survive this shell's session ending —
# critical when run-host.sh is invoked over SSM RunShellScript, which kills the
# command's process group on completion and would otherwise take the plumbing
# down with it (the enclave VM survives; its shell-child tunnels would not).
start_proxy() {
  setsid sh -c "exec vsock-proxy $1 $2 443 --num_workers $3 --config ${CONF}" </dev/null >/dev/null 2>&1 &
}
proxy_running() { pgrep -f "vsock-proxy $1 $2 " >/dev/null; }

# Preflight BEFORE touching the running proxies: a failure here must leave the
# current enclave's tunnels intact (a cutover that fails keeps serving). Every
# worker is a task in this script's cgroup; the proxies being replaced free
# theirs. cgroup v2 only; skipped (with a note) where the files are absent.
need=0
for entry in "${PROXIES[@]}"; do set -- $entry; need=$(( need + $3 + 1 )); done
cg="/sys/fs/cgroup$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup 2>/dev/null)"
if [ -r "$cg/pids.max" ] && [ -r "$cg/pids.current" ] && [ "$(cat "$cg/pids.max")" != "max" ]; then
  # Only proxies in THIS cgroup free budget here: a cutover over SSM replaces
  # proxies that ppq-enclave.service started, whose tasks count elsewhere.
  old=0
  for pid in $(pgrep -f 'vsock-proxy' || true); do
    [ "/sys/fs/cgroup$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup" 2>/dev/null)" = "$cg" ] || continue
    old=$(( old + $(ls "/proc/$pid/task" 2>/dev/null | wc -l) ))
  done
  avail=$(( $(cat "$cg/pids.max") - $(cat "$cg/pids.current") + old ))
  if [ "$need" -gt "$avail" ]; then
    echo ">> FATAL: vsock-proxies need ${need} tasks but this cgroup has ${avail} (pids.max $(cat "$cg/pids.max") at $cg). Lower VSOCK_WORKERS or raise TasksMax. Running proxies left untouched (#173)." >&2
    exit 1
  fi
  echo ">> vsock-proxy task budget: ${need} of ${avail} available"
else
  echo ">> vsock-proxy task budget: cgroup limit not readable; relying on the post-start check"
fi

pkill -f 'vsock-proxy' 2>/dev/null || true
# Wait for the old proxies to exit, so the check below cannot see a survivor.
for _ in $(seq 1 50); do pgrep -f 'vsock-proxy' >/dev/null || break; sleep 0.2; done
if pgrep -f 'vsock-proxy' >/dev/null; then
  pkill -9 -f 'vsock-proxy' 2>/dev/null || true
  sleep 1
fi
for entry in "${PROXIES[@]}"; do start_proxy $entry; done

# A proxy that exits leaves nothing behind but a missing tunnel: a dead settle
# proxy turns every chat into "502 authorization failed" and a silent browser
# fallback to the NON-private path. So check each one, restart any that died
# once, and refuse to continue if one is still down. A failure past the preflight
# (the budget was fine, so something else killed a proxy) exits BEFORE the
# running enclave is terminated, but its proxies are already replaced, so
# callers (boot-enclave.sh, the cutover) must treat it as a failed boot and retry.
PROXY_SETTLE_SECS="${PROXY_SETTLE_SECS:-3}"
sleep "${PROXY_SETTLE_SECS}"
for entry in "${PROXIES[@]}"; do
  set -- $entry
  if ! proxy_running "$1" "$2"; then
    echo ">> vsock-proxy $1 ($2) exited at startup; restarting once" >&2
    start_proxy $entry
  fi
done
sleep "${PROXY_SETTLE_SECS}"
dead=""
for entry in "${PROXIES[@]}"; do
  set -- $entry
  proxy_running "$1" "$2" || dead="${dead} $1($2)"
done
if [ -n "${dead}" ]; then
  echo ">> FATAL: vsock-proxy not running:${dead}. Check the TasksMax of this script's cgroup (#173)." >&2
  exit 1
fi
echo ">> ${#PROXIES[@]} vsock-proxies running"

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
# Fleet distribution (#52 scaling, step 3): after the local write, the blob is
# also published to S3 so every other box unseals the SAME certificate and
# EHBP identity at its next boot. Still ciphertext -- S3, like this listener,
# can store it and not open it. STORE_S3="" disables the upload: non-authority
# fleet boxes set it (boot-enclave.sh) and must never push over the authority's
# renewal. `-` not `:-`, so empty means disabled rather than default (#173).
# The PULL at boot is send-init.sh's STORE_S3_PULL, deliberately separate. The
# publish runs under the instance role; it needs s3:PutObject on the bucket
# (inline policy ppq-enclave-sealed-store on ppq-enclave-host).
STORE_S3="${STORE_S3-s3://ppq-enclave-sealed-store/acme-store.json}"
mkdir -p "$(dirname "$STORE_PATH")"
cat > /usr/local/bin/ppq-store-save <<EOSAVE
#!/bin/sh
# Invoked by socat per save; stdin is the sealed blob.
set -e
cat > "${STORE_PATH}.tmp" && mv -f "${STORE_PATH}.tmp" "${STORE_PATH}"
if [ -n "${STORE_S3}" ]; then
  aws s3 cp "${STORE_PATH}" "${STORE_S3}" --region "${REGION}" --only-show-errors \
    || logger -t ppq-store-save "S3 publish failed; local copy is current"
fi
EOSAVE
chmod 755 /usr/local/bin/ppq-store-save
pkill -f "VSOCK-LISTEN:${STORE_PORT}" 2>/dev/null || true
setsid sh -c "exec socat VSOCK-LISTEN:${STORE_PORT},reuseaddr,fork SYSTEM:/usr/local/bin/ppq-store-save" \
  </dev/null >/dev/null 2>&1 &
echo ">> sealed-store listener on vsock:${STORE_PORT} -> ${STORE_PATH}${STORE_S3:+ (+ ${STORE_S3})}"

# INBOUND_LISTEN_PORT lets the DEV host put this forwarder straight on :443,
# where production keeps it on :8443 behind nginx. That is not a shortcut: it is
# the phase-3 end state of #52 (no L7 proxy in the byte path), so dev exercises
# the topology production is moving toward, and it is what makes ACME
# TLS-ALPN-01 reachable without an nginx SNI split. Same script, different env.
INBOUND_LISTEN_PORT="${INBOUND_LISTEN_PORT:-8443}"
echo ">> starting inbound forwarder (public :${INBOUND_LISTEN_PORT} -> enclave vsock:8443)"
pkill -f "TCP4-LISTEN:${INBOUND_LISTEN_PORT}" 2>/dev/null || true
# backlog: socat's default listen backlog is 5. Behind nginx (511) that queue
# overflowed at 24 simultaneous connections and reset one of them (#52 step 5
# sweep, 2026-09-08) — a ceiling the whole box shares no matter how many
# workers run behind it. somaxconn on the host is 4096.
setsid sh -c "exec socat TCP4-LISTEN:${INBOUND_LISTEN_PORT},reuseaddr,fork,backlog=1024 VSOCK-CONNECT:${ENCLAVE_CID}:8443" </dev/null >/dev/null 2>&1 &

# The api path (api.ppq.ai): a second forwarder into vsock:8445, where the
# enclave expects a PROXY protocol header ahead of each TLS ClientHello (the
# v1 text line nginx's `proxy_protocol on` writes; v2 is also accepted for a
# future no-nginx variant). Empty (the default) = not started; the enclave's
# 8445 listener then simply sees no traffic. Set it to the socket path nginx's
# arm proxies to (scripts/nginx-pp-arm.conf: /run/ppq/pp.sock).
#
# The forwarder itself (validation, the 750 root:nginx directory, the 660
# root:nginx socket, the socat) lives in scripts/pp-forwarder.sh so a box whose
# enclave is already up can gain the arm without a restart; the reasoning for
# a unix socket rather than a loopback port is documented there.
INBOUND_PP_SOCKET="${INBOUND_PP_SOCKET:-}"
if [ -n "${INBOUND_PP_SOCKET}" ]; then
  INBOUND_PP_SOCKET="${INBOUND_PP_SOCKET}" ENCLAVE_CID="${ENCLAVE_CID}" bash "$(dirname "$0")/pp-forwarder.sh"
fi

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
