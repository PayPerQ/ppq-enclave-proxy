#!/usr/bin/env bash
# Confine each enclave host role to its own SSM parameter path.
#
#   ppq-enclave-host      -> /ppq-enclave/*      (production)
#   ppq-enclave-dev-host  -> /ppq-enclave-dev/*  (dev)
#
# WHY THIS FILE EXISTS
# --------------------
# Both roles carry AmazonSSMManagedInstanceCore, which the SSM agent needs for
# the run-command steps every workflow uses. That managed policy also grants
# ssm:GetParameter and ssm:GetParameters on "*". And the AWS-managed aws/ssm KMS
# key lets ANY principal in the account decrypt through SSM, with no IAM grant
# needed. Together, until this script ran, either host could read and decrypt
# every SecureString in the account: the dev box could read production's
# plaintext provider keys and settle secret, and the production hosts could read
# the dev secrets and the ops webhook. DEV-ENCLAVE.md described the dev/prod
# split as enforced; it was not.
#
# Audited 2026-09-24 against CloudTrail event history (2026-07-06 onward, 1,407
# parameter reads): no read ever crossed the boundary, so nothing was rotated.
#
# The fix is an explicit Deny on every parameter read outside the role's own
# path. An explicit Deny beats the managed policy's Allow. Public AWS parameters
# (/aws/*) stay readable, and nothing the SSM agent itself needs is touched.
# Idempotent; it prints a verification from the policy simulator.
set -euo pipefail

REGION="${REGION:-us-east-1}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

scope() {
  local role="$1" own="$2"
  aws iam put-role-policy --role-name "$role" --policy-name only-own-parameters --policy-document "$(cat <<JSON
{"Version":"2012-10-17","Statement":[{
  "Sid":"OnlyOwnParameters","Effect":"Deny","Action":"ssm:GetParameter*",
  "NotResource":["arn:aws:ssm:*:${ACCOUNT}:parameter/${own}/*","arn:aws:ssm:*::parameter/aws/*"]
}]}
JSON
)"
  echo "== $role: parameter reads confined to /$own/*"
}

scope ppq-enclave-host ppq-enclave
scope ppq-enclave-dev-host ppq-enclave-dev

echo "== verification (the roles' real policies, via the policy simulator)"
fail=0
check() {
  local role="$1" param="$2" want="$3" got
  got=$(aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::${ACCOUNT}:role/${role}" \
    --action-names ssm:GetParameter --resource-arns "arn:aws:ssm:${REGION}:${ACCOUNT}:parameter${param}" \
    --query 'EvaluationResults[0].EvalDecision' --output text)
  printf '   %-22s %-48s %-13s %s\n' "$role" "$param" "$got" "$([ "$got" = "$want" ] && echo ok || { echo "EXPECTED $want"; })"
  [ "$got" = "$want" ] || fail=1
}
check ppq-enclave-host     /ppq-enclave/openrouter-key                   allowed
check ppq-enclave-host     /ppq-enclave-dev/openrouter-key               explicitDeny
check ppq-enclave-host     /ppq-ops/enclave-scaling-alerts/slack-webhook explicitDeny
check ppq-enclave-dev-host /ppq-enclave-dev/openrouter-key               allowed
check ppq-enclave-dev-host /ppq-enclave/openrouter-key                   explicitDeny
check ppq-enclave-dev-host /ppq-enclave/settle-secret                    explicitDeny
check ppq-enclave-dev-host /ppq-ops/enclave-scaling-alerts/slack-webhook explicitDeny
[ "$fail" = 0 ] || { echo "verification failed" >&2; exit 1; }
