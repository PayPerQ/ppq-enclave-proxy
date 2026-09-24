#!/usr/bin/env bash
# Configure how the enclave fleet scales: where it may launch, how long a box
# drains before it is removed, what it reports, and the signal it scales on.
# Idempotent — re-run it after recreating a load balancer or target group.
#
# WHY THIS FILE EXISTS
# --------------------
# The autoscaling group and its policies were configured by hand, and the
# configuration drifted into scaling on the wrong thing. Audited 2026-09-24:
#
#   * Both scaling alarms read ActiveFlowCount on the ppq-enclave load
#     balancer (enclave.ppq.ai). api.ppq.ai has its own load balancer, and it
#     carries ~95% of new connections. The fleet was blind to nearly all of its
#     real traffic: api.ppq.ai sat above the scale-out threshold for about a
#     quarter of a week and never triggered anything.
#   * The alarms compared a load-balancer TOTAL against fixed thresholds
#     (>120 out, <30 in). A total does not fall when a box is added, so any
#     sustained burst ratcheted the fleet to its maximum and any lull dropped
#     it to its minimum. On 2026-09-23 a burst on enclave.ppq.ai took it from
#     2 boxes to 5 in twelve minutes, the last one arriving after the burst had
#     faded; step scale-in then removed three boxes in six minutes.
#   * us-east-1e was a launch subnet. c6i.2xlarge is not offered there, so a
#     scale-out placed in it failed (2026-09-13) before retrying elsewhere.
#   * A removed box drained for 60 s, well short of the pass-through's 240 s
#     wait (v0.24.0) and of long reasoning streams.
#
# The fix scales on connections PER HEALTHY BOX across BOTH load balancers,
# which falls as boxes are added, so target tracking converges instead of
# ratcheting. Over five days that signal ran p50 38, p99 109, max 219 per box,
# with the busiest box never above 7.5% CPU. The target of 150 sits above
# routine peaks, so it does not react to noise, and still adds capacity on a
# genuine surge. Raise it after a load test; nothing measured so far is near
# the fleet's limit.
#
# NOT YET HERE (see README "Autoscaling"): each box's own open-stream count as
# the signal, a termination hook that waits for streams to finish, scaling
# notifications into Slack, and host logs in CloudWatch Logs.
set -euo pipefail

REGION="${REGION:-us-east-1}"
ASG="${ASG:-ppq-enclave-fleet}"
TARGET_FLOWS_PER_BOX="${TARGET_FLOWS_PER_BOX:-150}"
DRAIN_SECONDS="${DRAIN_SECONDS:-300}"
R=(--region "$REGION")

# Every public subnet except us-east-1e (subnet-aa6b7395, use1-az3), where
# c6i.2xlarge is not offered. The load balancers keep all six: an NLB node in
# 1e with cross-zone on is harmless, only a box launched there fails.
LAUNCH_SUBNETS="subnet-185e967f,subnet-db14d9f5,subnet-cb32a581,subnet-ebf231b7,subnet-adaa3ca2"

lb_dim() { aws elbv2 describe-load-balancers "${R[@]}" --names "$1" --query 'LoadBalancers[0].LoadBalancerArn' --output text | sed 's|.*:loadbalancer/||'; }
tg_arn() { aws elbv2 describe-target-groups "${R[@]}" --names "$1" --query 'TargetGroups[0].TargetGroupArn' --output text; }

echo "== launch subnets (no us-east-1e); capacity rebalancing off (Spot-only; this fleet is on-demand)"
aws autoscaling update-auto-scaling-group "${R[@]}" --auto-scaling-group-name "$ASG" \
  --vpc-zone-identifier "$LAUNCH_SUBNETS" --no-capacity-rebalance

echo "== group metrics at 1-minute granularity (desired / in-service / pending / terminating)"
aws autoscaling enable-metrics-collection "${R[@]}" --auto-scaling-group-name "$ASG" --granularity 1Minute

echo "== ${DRAIN_SECONDS} s drain on both target groups"
for tg in ppq-api-tls ppq-enclave-tls; do
  aws elbv2 modify-target-group-attributes "${R[@]}" --target-group-arn "$(tg_arn "$tg")" \
    --attributes Key=deregistration_delay.timeout_seconds,Value="$DRAIN_SECONDS" >/dev/null
  echo "   $tg"
done

API_LB=$(lb_dim ppq-api)
ENC_LB=$(lb_dim ppq-enclave)
API_TG=$(tg_arn ppq-api-tls | sed 's|.*:||')   # targetgroup/ppq-api-tls/<id>
# Both target groups hold the same boxes, so one group's healthy count is the
# denominator. The build host is a target but not in the ASG; it still takes
# its share of connections, so dividing by it is right.
CONFIG=$(mktemp)
trap 'rm -f "$CONFIG"' EXIT
cat > "$CONFIG" <<JSON
{
  "TargetValue": ${TARGET_FLOWS_PER_BOX},
  "CustomizedMetricSpecification": {
    "Metrics": [
      {"Id": "api", "ReturnData": false,
       "MetricStat": {"Metric": {"Namespace": "AWS/NetworkELB", "MetricName": "ActiveFlowCount_TCP",
         "Dimensions": [{"Name": "LoadBalancer", "Value": "${API_LB}"}]}, "Stat": "Average"}},
      {"Id": "enc", "ReturnData": false,
       "MetricStat": {"Metric": {"Namespace": "AWS/NetworkELB", "MetricName": "ActiveFlowCount_TCP",
         "Dimensions": [{"Name": "LoadBalancer", "Value": "${ENC_LB}"}]}, "Stat": "Average"}},
      {"Id": "hosts", "ReturnData": false,
       "MetricStat": {"Metric": {"Namespace": "AWS/NetworkELB", "MetricName": "HealthyHostCount",
         "Dimensions": [{"Name": "TargetGroup", "Value": "${API_TG}"}, {"Name": "LoadBalancer", "Value": "${API_LB}"}]},
         "Stat": "Average"}},
      {"Id": "perbox", "ReturnData": true, "Label": "TCP flows per healthy enclave box (api + enclave NLBs)",
       "Expression": "IF(hosts > 0, (FILL(api, 0) + FILL(enc, 0)) / hosts, FILL(api, 0) + FILL(enc, 0))"}
    ]
  },
  "DisableScaleIn": false
}
JSON

echo "== target tracking: ${TARGET_FLOWS_PER_BOX} flows per healthy box (api ${API_LB}, enclave ${ENC_LB})"
aws autoscaling put-scaling-policy "${R[@]}" --auto-scaling-group-name "$ASG" \
  --policy-name flows-per-box-target --policy-type TargetTrackingScaling \
  --estimated-instance-warmup 300 --target-tracking-configuration "file://$CONFIG" \
  --query 'Alarms[].AlarmName' --output text | tr '\t' '\n' | sed 's/^/   alarm /'

echo "== remove the legacy step policies and their alarms (no-op once gone)"
for p in flows-scale-out flows-scale-in; do
  if aws autoscaling delete-policy "${R[@]}" --auto-scaling-group-name "$ASG" --policy-name "$p" 2>/dev/null; then
    echo "   removed policy $p"
  fi
done
aws cloudwatch delete-alarms "${R[@]}" --alarm-names ppq-enclave-fleet-flows-high ppq-enclave-fleet-flows-low

echo "== result"
aws autoscaling describe-policies "${R[@]}" --auto-scaling-group-name "$ASG" \
  --query 'ScalingPolicies[].[PolicyName,PolicyType]' --output text | sed 's/^/   /'
