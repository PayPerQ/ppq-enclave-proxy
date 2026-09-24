#!/usr/bin/env bash
# Post the enclave fleet's autoscaling events to Slack.
#
#   EventBridge rule (aws.autoscaling, this group only)
#     -> Lambda ppq-enclave-scaling-alerts (scaling-alerts/index.mjs)
#     -> the Slack incoming webhook stored in SSM at $WEBHOOK_PARAM
#
# Idempotent: re-run after editing the function. `--test` posts a one-line
# connectivity check to the channel instead of deploying.
#
# The webhook is a SecureString OUTSIDE /ppq-enclave/: the enclave host role
# may read every parameter under that prefix, and the hosts are untrusted by
# design. Store it once, without echoing it, e.g. from horse-power's own
# enclave-alerts setting:
#
#   az webapp config appsettings list --name ppq-backend-us --resource-group ppq-backend \
#     --query "[?name=='ENCLAVE_ALERTS_SLACK_WEBHOOK_URL'].value" -o tsv | tr -d '\n' |
#   aws ssm put-parameter --region us-east-1 --type SecureString --overwrite \
#     --name /ppq-ops/enclave-scaling-alerts/slack-webhook --value file:///dev/stdin
#
# Until it exists the function logs a warning and posts nothing, so this can be
# deployed first.
set -euo pipefail

REGION="${REGION:-us-east-1}"
ASG="${ASG:-ppq-enclave-fleet}"
FN="${FN:-ppq-enclave-scaling-alerts}"
ROLE="${ROLE:-ppq-enclave-scaling-alerts}"
RULE="${RULE:-ppq-enclave-fleet-scaling-events}"
WEBHOOK_PARAM="${WEBHOOK_PARAM:-/ppq-ops/enclave-scaling-alerts/slack-webhook}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R=(--region "$REGION")

if [ "${1:-}" = "--test" ]; then
  out=$(mktemp); trap 'rm -f "$out"' EXIT
  # An invoke can succeed at the API level while the function itself failed, so
  # check both FunctionError and the handler's own {"posted": true}.
  ferr=$(aws lambda invoke "${R[@]}" --function-name "$FN" --cli-binary-format raw-in-base64-out \
    --payload '{"ppqTest": true}' "$out" --query 'FunctionError' --output text)
  echo "result: $(cat "$out")"
  if [ "$ferr" != "None" ]; then echo "FAILED: the function raised ($ferr)" >&2; exit 1; fi
  if ! grep -q '"posted":true' "$out"; then echo "FAILED: nothing was posted" >&2; exit 1; fi
  echo "posted: check the enclave alerts channel"
  exit 0
fi

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
SSM_KEY_ARN=$(aws kms describe-key "${R[@]}" --key-id alias/aws/ssm --query KeyMetadata.Arn --output text)

echo "== role $ROLE"
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" --description "Posts ppq-enclave-fleet scaling events to Slack" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  echo "   created"
fi
# Least privilege: write its own log group, read ONE parameter, decrypt it only through SSM.
aws iam put-role-policy --role-name "$ROLE" --policy-name logs-and-webhook --policy-document "$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],
   "Resource":"arn:aws:logs:${REGION}:${ACCOUNT}:log-group:/aws/lambda/${FN}:*"},
  {"Effect":"Allow","Action":"ssm:GetParameter",
   "Resource":"arn:aws:ssm:${REGION}:${ACCOUNT}:parameter${WEBHOOK_PARAM}"},
  {"Effect":"Allow","Action":"kms:Decrypt","Resource":"${SSM_KEY_ARN}",
   "Condition":{"StringEquals":{"kms:ViaService":"ssm.${REGION}.amazonaws.com"}}}
]}
JSON
)"
ROLE_ARN=$(aws iam get-role --role-name "$ROLE" --query Role.Arn --output text)

echo "== log group, 30-day retention"
aws logs create-log-group "${R[@]}" --log-group-name "/aws/lambda/$FN" 2>/dev/null || true
aws logs put-retention-policy "${R[@]}" --log-group-name "/aws/lambda/$FN" --retention-in-days 30

echo "== function $FN"
ZIP=$(mktemp -d)/fn.zip
( cd "$HERE/scaling-alerts" && zip -q -j "$ZIP" index.mjs )
ENV="Variables={ASG_NAME=$ASG,WEBHOOK_PARAM=$WEBHOOK_PARAM}"
if aws lambda get-function "${R[@]}" --function-name "$FN" >/dev/null 2>&1; then
  aws lambda update-function-code "${R[@]}" --function-name "$FN" --zip-file "fileb://$ZIP" >/dev/null
  aws lambda wait function-updated "${R[@]}" --function-name "$FN"
  aws lambda update-function-configuration "${R[@]}" --function-name "$FN" --role "$ROLE_ARN" \
    --runtime nodejs22.x --handler index.handler --timeout 10 --memory-size 128 --environment "$ENV" >/dev/null
  echo "   updated"
else
  # A new role takes a few seconds to become assumable by Lambda.
  for i in $(seq 1 12); do
    if aws lambda create-function "${R[@]}" --function-name "$FN" --role "$ROLE_ARN" \
         --runtime nodejs22.x --architectures arm64 --handler index.handler --timeout 10 --memory-size 128 \
         --environment "$ENV" --zip-file "fileb://$ZIP" \
         --description "Posts ppq-enclave-fleet scaling events to Slack" >/dev/null 2>"$ZIP.err"; then
      echo "   created"; break
    fi
    grep -q "cannot be assumed" "$ZIP.err" || { cat "$ZIP.err" >&2; exit 1; }
    [ "$i" = 12 ] && { cat "$ZIP.err" >&2; exit 1; }
    sleep 5
  done
fi
aws lambda wait function-updated "${R[@]}" --function-name "$FN"
FN_ARN=$(aws lambda get-function "${R[@]}" --function-name "$FN" --query Configuration.FunctionArn --output text)

echo "== EventBridge rule $RULE"
PATTERN=$(cat <<JSON
{"source":["aws.autoscaling"],
 "detail-type":["EC2 Instance Launch Successful","EC2 Instance Launch Unsuccessful",
                "EC2 Instance Terminate Successful","EC2 Instance Terminate Unsuccessful"],
 "detail":{"AutoScalingGroupName":["${ASG}"]}}
JSON
)
RULE_ARN=$(aws events put-rule "${R[@]}" --name "$RULE" --event-pattern "$PATTERN" --state ENABLED \
  --description "ppq-enclave-fleet launches and terminations -> Slack" --query RuleArn --output text)
# Without this grant the rule matches and the target is set, but EventBridge
# cannot invoke the function and alerts silently never arrive. Keep an existing
# statement only if it names this rule; replace it otherwise; fail on errors.
SID="eventbridge-$RULE"
have=$(aws lambda get-policy "${R[@]}" --function-name "$FN" --query Policy --output text 2>/dev/null |
  python3 -c 'import sys,json
try: p=json.load(sys.stdin)
except Exception: p={"Statement":[]}
for s in p.get("Statement",[]):
  if s.get("Sid")==sys.argv[1]:
    print(s.get("Condition",{}).get("ArnLike",{}).get("AWS:SourceArn","")); break' "$SID" || true)
if [ "$have" != "$RULE_ARN" ]; then
  [ -n "$have" ] && aws lambda remove-permission "${R[@]}" --function-name "$FN" --statement-id "$SID"
  aws lambda add-permission "${R[@]}" --function-name "$FN" --statement-id "$SID" \
    --action lambda:InvokeFunction --principal events.amazonaws.com --source-arn "$RULE_ARN" >/dev/null
  echo "   granted EventBridge invoke for $RULE"
else
  echo "   EventBridge invoke already granted for $RULE"
fi
aws events put-targets "${R[@]}" --rule "$RULE" --targets "Id=scaling-alerts,Arn=$FN_ARN" --query FailedEntryCount --output text |
  { read -r n; [ "$n" = 0 ] || { echo "put-targets failed ($n)" >&2; exit 1; }; }

echo "== rule matches a scale-out from this group, and not one from another group"
sample() {
  printf '{"id":"1","account":"%s","source":"aws.autoscaling","time":"2026-09-24T00:00:00Z","region":"%s","resources":[],"detail-type":"EC2 Instance Launch Successful","detail":{"AutoScalingGroupName":"%s"}}' \
    "$ACCOUNT" "$REGION" "$1"
}
aws events test-event-pattern "${R[@]}" --event-pattern "$PATTERN" --event "$(sample "$ASG")" --query Result --output text | sed 's/^/   this group: /'
aws events test-event-pattern "${R[@]}" --event-pattern "$PATTERN" --event "$(sample other-group)" --query Result --output text | sed 's/^/   other group: /'

if aws ssm get-parameter "${R[@]}" --name "$WEBHOOK_PARAM" --query Parameter.Type --output text >/dev/null 2>&1; then
  echo "== webhook present; run '$0 --test' to post a connectivity check"
else
  echo "== webhook NOT stored yet at $WEBHOOK_PARAM; nothing will post until it is (see the header)"
fi
