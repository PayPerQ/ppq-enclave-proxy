#!/usr/bin/env bash
# The SECOND Network Load Balancer, for api.ppq.ai (plan W2.1). Same shape as
# scripts/fleet/create-nlb.sh (L4 passthrough, TLS still ends in the enclave)
# with the two differences that whole design turns on:
#
#   * client-IP preservation ON  -- the target sees the real peer, so nginx's
#     :8445 arm can write it into the PROXY v1 header (nginx-pp-arm.conf).
#     The hairpin failure mode that keeps it OFF on the enclave.ppq.ai NLB
#     does not apply: nothing on a box connects to api.ppq.ai through this
#     NLB (settles go to backend.ppq.ai), and the drift check does not visit
#     the api path by IP.
#   * proxy_protocol_v2 OFF      -- nginx does not parse an inbound header;
#     an NLB v2 header would reach the enclave as a second header.
#
# Target port 8445 on every box (nginx arm -> /run/ppq/pp.sock -> vsock:8445),
# health check HTTPS /health on 8445, which exercises the arm end to end
# (header written, stripped in the enclave, TLS completed, /health served).
# The security group opens 8445 to the world because, with preservation on,
# the packets carry the CLIENT's source address, not the NLB's.
#
# The target group is attached to the autoscaling group, so every fleet box
# registers itself; a box is healthy here only once it boots with
# fleet-config inbound_pp_socket set and the arm installed in its AMI. The
# build host is NOT registered here: it gains the arm and pass-through at the
# next cutover (the workflow reads both from fleet-config) and can be added
# then with `aws elbv2 register-targets`.
#
# DNS is deliberately not touched: api.lb.ppq.ai's enclave-side weighted
# record (weight 0, health-checked) is added once the enclave holds a
# certificate for api.ppq.ai (plan W4), and api.ppq.ai itself moves only at
# the flip.
#
#   bash scripts/fleet/create-api-nlb.sh       # us-east-1; AWS_PROFILE if you need one
set -euo pipefail
R=(--region us-east-1)
VPC=vpc-7ef3f705
SUBNETS="subnet-185e967f subnet-db14d9f5 subnet-cb32a581 subnet-ebf231b7 subnet-aa6b7395 subnet-adaa3ca2"
SG=sg-07e8ebbee4cb4c7c4          # the fleet's (and build host's) security group
ASG=ppq-enclave-fleet
TG_NAME=ppq-api-tls
LB_NAME=ppq-api

echo "== target group: TCP 8445, health check HTTPS /health on 8445"
TG=$(aws elbv2 describe-target-groups --names "$TG_NAME" "${R[@]}" --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true)
if [ -z "$TG" ] || [ "$TG" = None ]; then
  TG=$(aws elbv2 create-target-group --name "$TG_NAME" --protocol TCP --port 8445 --vpc-id "$VPC" \
    --target-type instance --health-check-protocol HTTPS --health-check-port 8445 --health-check-path /health \
    --matcher HttpCode=200 --health-check-interval-seconds 10 --healthy-threshold-count 2 --unhealthy-threshold-count 2 \
    --tags Key=Name,Value="$TG_NAME" "${R[@]}" --query 'TargetGroups[0].TargetGroupArn' --output text)
fi
echo "$TG"
aws elbv2 modify-target-group-attributes --target-group-arn "$TG" "${R[@]}" \
  --attributes Key=preserve_client_ip.enabled,Value=true Key=proxy_protocol_v2.enabled,Value=false Key=deregistration_delay.timeout_seconds,Value=60 >/dev/null
aws elbv2 describe-target-group-attributes --target-group-arn "$TG" "${R[@]}" \
  --query "Attributes[?Key=='preserve_client_ip.enabled' || Key=='proxy_protocol_v2.enabled'].[Key,Value]" --output text

echo "== NLB: internet-facing, all six public subnets, cross-zone, TCP 443 -> target group"
LB=$(aws elbv2 describe-load-balancers --names "$LB_NAME" "${R[@]}" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)
if [ -z "$LB" ] || [ "$LB" = None ]; then
  # shellcheck disable=SC2086
  LB=$(aws elbv2 create-load-balancer --name "$LB_NAME" --type network --scheme internet-facing --ip-address-type ipv4 \
    --subnets $SUBNETS --tags Key=Name,Value="$LB_NAME" "${R[@]}" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
fi
echo "$LB"
aws elbv2 modify-load-balancer-attributes --load-balancer-arn "$LB" "${R[@]}" \
  --attributes Key=load_balancing.cross_zone.enabled,Value=true >/dev/null
if [ "$(aws elbv2 describe-listeners --load-balancer-arn "$LB" "${R[@]}" --query 'length(Listeners)' --output text)" = 0 ]; then
  aws elbv2 create-listener --load-balancer-arn "$LB" --protocol TCP --port 443 \
    --default-actions Type=forward,TargetGroupArn="$TG" "${R[@]}" --query 'Listeners[0].ListenerArn' --output text
fi

echo "== security group: 8445 from anywhere (preservation on = client source addresses)"
aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 8445 --cidr 0.0.0.0/0 "${R[@]}" >/dev/null 2>&1 \
  || echo "   (8445 rule already present)"

echo "== attach the target group to $ASG (fleet boxes register themselves)"
aws autoscaling attach-load-balancer-target-groups --auto-scaling-group-name "$ASG" --target-group-arns "$TG" "${R[@]}"

aws elbv2 wait load-balancer-available --load-balancer-arns "$LB" "${R[@]}"
DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$LB" "${R[@]}" --query 'LoadBalancers[0].DNSName' --output text)
echo "== targets"
aws elbv2 describe-target-health --target-group-arn "$TG" "${R[@]}" \
  --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State,TargetHealth.Reason]' --output text
echo "TG=$TG"; echo "LB=$LB"; echo "NLB_DNS=$DNS"
echo "A box turns healthy here once it runs the arm: fleet-config inbound_pp_socket=/run/ppq/pp.sock + an AMI with install-pp-arm.sh applied, then an instance refresh."
