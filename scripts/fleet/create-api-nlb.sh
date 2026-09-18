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
# ATTACHING THE GROUP TO THE AUTOSCALING GROUP IS A SEPARATE, LATER STEP
# (ATTACH_ASG=1). The ASG's health check type is ELB, and an instance counts
# as unhealthy when ANY attached target group reports it unhealthy. A box
# whose AMI does not yet carry the arm fails this group's 8445 check, so
# attaching before the fleet AMI has the arm makes the ASG terminate and
# relaunch every box once the grace period passes, about every six minutes,
# for ever. That happened on 2026-09-18 (a rollback to a pre-arm AMI while
# the group was attached). Attach only once a box booted from the CURRENT
# launch template turns healthy here on its own after being registered by
# hand; detach again (`aws autoscaling detach-load-balancer-target-groups`)
# before any refresh onto an AMI without the arm. The build host is not
# registered here either: it gains the arm and pass-through at the next
# cutover and can be added then with `aws elbv2 register-targets`.
#
# DNS is deliberately not touched: api.lb.ppq.ai's enclave-side weighted
# record (weight 0, health-checked) is added once the enclave holds a
# certificate for api.ppq.ai (plan W4), and api.ppq.ai itself moves only at
# the flip.
#
#   bash scripts/fleet/create-api-nlb.sh                 # us-east-1; AWS_PROFILE if you need one
#   ATTACH_ASG=1 bash scripts/fleet/create-api-nlb.sh    # also attach the group to the ASG (see below)
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
# A target group's protocol, port, target type and VPC cannot change after
# creation; an existing group with a different shape is not "ours" and must
# not be silently reused (a TCP:443 group here would send the NLB's health
# checks and traffic past the arm).
read -r P PT TT V < <(aws elbv2 describe-target-groups --target-group-arns "$TG" "${R[@]}" \
  --query 'TargetGroups[0].[Protocol,Port,TargetType,VpcId]' --output text)
[ "$P/$PT/$TT/$V" = "TCP/8445/instance/$VPC" ] \
  || { echo "target group $TG_NAME is $P:$PT $TT in $V, expected TCP:8445 instance in $VPC; delete or rename it" >&2; exit 1; }
# Health-check settings only apply at creation, so an existing group is
# reconciled explicitly: the check must be HTTPS /health on 8445 (the whole
# arm), never a bare TCP check that would call nginx healthy with the enclave
# down behind it.
aws elbv2 modify-target-group --target-group-arn "$TG" "${R[@]}" \
  --health-check-protocol HTTPS --health-check-port 8445 --health-check-path /health --matcher HttpCode=200 \
  --health-check-interval-seconds 10 --healthy-threshold-count 2 --unhealthy-threshold-count 2 >/dev/null
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
# Reconcile the TCP 443 listener: create it if absent, otherwise make sure it
# forwards to THIS target group.
LSN=$(aws elbv2 describe-listeners --load-balancer-arn "$LB" "${R[@]}" --query "Listeners[?Port==\`443\`].ListenerArn | [0]" --output text 2>/dev/null || true)
if [ -z "$LSN" ] || [ "$LSN" = None ]; then
  aws elbv2 create-listener --load-balancer-arn "$LB" --protocol TCP --port 443 \
    --default-actions Type=forward,TargetGroupArn="$TG" "${R[@]}" --query 'Listeners[0].ListenerArn' --output text
else
  # A listener's protocol cannot change: a TLS listener here would terminate
  # TLS on the NLB, ahead of nginx and the enclave, and must be replaced.
  read -r LPROTO CUR < <(aws elbv2 describe-listeners --listener-arns "$LSN" "${R[@]}" --query 'Listeners[0].[Protocol,DefaultActions[0].TargetGroupArn]' --output text)
  [ "$LPROTO" = TCP ] || { echo "listener on 443 is $LPROTO, expected TCP (L4 passthrough); delete it and re-run" >&2; exit 1; }
  if [ "$CUR" != "$TG" ]; then
    aws elbv2 modify-listener --listener-arn "$LSN" --default-actions Type=forward,TargetGroupArn="$TG" "${R[@]}" --query 'Listeners[0].ListenerArn' --output text
  else
    echo "$LSN (already forwards to the target group)"
  fi
fi

echo "== security group: 8445 from anywhere (preservation on = client source addresses)"
# Only "already there" is fine to ignore; any other failure (auth, throttling,
# a wrong group id) would leave 8445 closed with the script reporting success.
if ! out=$(aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 8445 --cidr 0.0.0.0/0 "${R[@]}" 2>&1 >/dev/null); then
  case "$out" in
    *InvalidPermission.Duplicate*) echo "   (8445 rule already present)";;
    *) echo "$out" >&2; exit 1;;
  esac
fi

if [ "${ATTACH_ASG:-0}" = 1 ]; then
  echo "== attach the target group to $ASG (fleet boxes register themselves; see the header on when this is safe)"
  aws autoscaling attach-load-balancer-target-groups --auto-scaling-group-name "$ASG" --target-group-arns "$TG" "${R[@]}"
else
  echo "== not attaching to $ASG (ATTACH_ASG=1 does; read the header first)"
fi

aws elbv2 wait load-balancer-available --load-balancer-arns "$LB" "${R[@]}"
DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$LB" "${R[@]}" --query 'LoadBalancers[0].DNSName' --output text)
echo "== targets"
aws elbv2 describe-target-health --target-group-arn "$TG" "${R[@]}" \
  --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State,TargetHealth.Reason]' --output text
echo "TG=$TG"; echo "LB=$LB"; echo "NLB_DNS=$DNS"
echo "A box turns healthy here once it runs the arm: fleet-config inbound_pp_socket=/run/ppq/pp.sock + an AMI with install-pp-arm.sh applied, then an instance refresh."
