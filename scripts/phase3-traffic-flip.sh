#!/usr/bin/env bash
# Move ORDINARY enclave.ppq.ai traffic off nginx and onto the enclave (#52 phase 3).
#
# This is the moment real user requests start terminating inside the enclave
# instead of at nginx. Everything before it was preparation; this is the change
# in what the system IS.
#
# NOT DESTRUCTIVE, and that is deliberate: the rollback is restoring one file
# and reloading nginx, which takes seconds and needs no EIF. That is exactly why
# obtaining the certificate was kept separate from moving traffic -- bundling
# them would have made the rollback a 25-minute rebuild.
#
# Run on i-0609bf23c4b57a48e via SSM:
#   aws ssm send-command --instance-ids i-0609bf23c4b57a48e \
#     --document-name AWS-RunShellScript --profile ppq-enclave --region us-east-1 \
#     --parameters 'commands=["bash /home/ec2-user/ppq-enclave-proxy/scripts/phase3-traffic-flip.sh 2>&1"]' \
#     --query Command.CommandId --output text
set -euo pipefail

CONF=/etc/nginx/nginx.conf
BAK="/etc/nginx/nginx.conf.bak-flip-$(date +%s)"

# ── PRE-FLIGHT ───────────────────────────────────────────────────────────────
# Refuse unless the enclave ALREADY serves a browser-trusted certificate for
# enclave.ppq.ai. Flipping without one does not degrade, it takes the hostname
# down: every client gets a name-mismatched or untrusted certificate.
echo ">> pre-flight: what does the enclave serve for enclave.ppq.ai?"
CERT=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername enclave.ppq.ai 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true)
SANS=$(printf '%s' "$CERT" | grep -A1 'Subject Alternative Name' | tail -1 || true)
ISSUER=$(printf '%s' "$CERT" | grep -m1 'Issuer:' || true)
echo "   SANs  : ${SANS:-<none>}"
echo "   issuer: ${ISSUER:-<none>}"

case "$SANS" in
  *enclave.ppq.ai*) ;;
  *) echo "ABORT: the enclave holds no certificate covering enclave.ppq.ai"; exit 1 ;;
esac
case "$ISSUER" in
  *STAGING*) echo "ABORT: that certificate is from Let's Encrypt STAGING; browsers reject it"; exit 1 ;;
  *"Let's Encrypt"*) ;;
  *) echo "ABORT: unexpected issuer; refusing to move traffic onto it"; exit 1 ;;
esac

if grep -q '"enclave.ppq.ai:0"' "$CONF"; then
  echo "ALREADY FLIPPED — nothing to do"; exit 0
fi

cp -a "$CONF" "$BAK"; echo ">> backup: $BAK"

# The ALPN split already routes the acme-tls/1 challenge for this name. Adding
# the ':0' arm sends ordinary traffic the same way.
python3 - "$CONF" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
needle = '"enclave.ppq.ai:1"         127.0.0.1:8443;'
if needle not in s:
    sys.exit('ABORT: ALPN split arm not found; apply the ALPN split first')
s = s.replace(needle, needle + '\n        "enclave.ppq.ai:0"         127.0.0.1:8443;', 1)
open(p, 'w').write(s)
print('>> rewrote the map')
PY

rollback() {
  echo "!! $1 — rolling back"
  cp -a "$BAK" "$CONF"
  nginx -t && systemctl reload nginx
  echo ">> ROLLED BACK to nginx termination"
  exit 1
}

nginx -t || rollback "nginx -t failed"
systemctl reload nginx
echo ">> reloaded"
sleep 3

# Verify from the PUBLIC side, with certificate verification ON. A 200 with
# verify=0 is the whole claim: a real client, trusting the real CA bundle,
# talking TLS the enclave terminated itself.
OUT=$(curl -s -o /dev/null -w "%{http_code} verify=%{ssl_verify_result}" --max-time 20 https://enclave.ppq.ai/health || echo "unreachable")
echo ">> enclave.ppq.ai -> $OUT"
[ "$OUT" = "200 verify=0" ] || rollback "public check failed ($OUT)"

echo ">> FLIP OK — enclave.ppq.ai now terminates TLS inside the enclave"
echo ">> rollback if needed: cp -a $BAK $CONF && nginx -t && systemctl reload nginx"
