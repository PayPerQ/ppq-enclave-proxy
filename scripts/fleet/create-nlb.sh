#!/usr/bin/env bash
# The Network Load Balancer in front of the enclave fleet (#52 scaling, step 4).
# Ran once on 2026-09-08; kept here so the shape of the live resources is on
# record and reproducible. It creates the target group + NLB + listener and
# registers the build host; DNS (enclave.ppq.ai CNAME -> NLB) is a separate,
# deliberate step. The ASG registers fleet boxes into the same target group.
#
# Live resources (us-east-1, account 287432920037):
#   NLB            ppq-enclave   ppq-enclave-1fad105b759633c2.elb.us-east-1.amazonaws.com
#   target group   ppq-enclave-tls  (TCP 443, health = HTTPS /health, instance targets)
#   ASG            ppq-enclave-fleet  (launch template lt-0ace55ca5ee03e8e6)
#   build host     i-0609bf23c4b57a48e  EIP 3.218.235.103 = enclave-direct.ppq.ai
#
# The NLB is L4 passthrough (TCP listener, no TLS termination): the client's TLS
# still ends inside the enclave, which is what the trust claim rests on.
#
# CLIENT IP PRESERVATION IS OFF, ON PURPOSE (2026-09-08). With it on, a client
# that reaches the same box both through the NLB and directly (the EIP) can
# present the same source ip:port on both paths; the target sees a duplicated
# 4-tuple and one of the connections stalls until it times out. AWS documents
# this ("Intermittent TCP connection establishment failure", NLB troubleshooting
# guide) and recommends disabling preservation. It bit the drift check, which
# visits every box by IP *and* enclave.ppq.ai from the same runner: three CI runs
# timed out on /attestation by direct IP while curl from anywhere else was fine.
# Hairpinning (a box calling enclave.ppq.ai) is also only safe with it off.
# Cost: the box logs the NLB's private address instead of the client's on the
# enclave.ppq.ai path. Nothing consumes the client IP (server.mjs reads no
# x-forwarded-for; nginx-sni-split.conf only logs it) -- and the parent seeing
# less is the right direction for this project. Proxy protocol v2 is NOT an
# option: it cannot be enabled per-SNI, and enclave-direct's plain TLS server
# would read the header as ClientHello garbage.
#
#   bash scripts/fleet/create-nlb.sh          # --profile ppq-enclave, us-east-1
set -euo pipefail
P=(--profile ppq-enclave --region us-east-1)
I=i-0609bf23c4b57a48e
VPC=vpc-7ef3f705
SUBNETS="subnet-185e967f subnet-db14d9f5 subnet-cb32a581 subnet-ebf231b7 subnet-aa6b7395 subnet-adaa3ca2"

echo "== target group: TCP 443, health check HTTPS /health (NLB does not verify certs)"
TG=$(aws elbv2 create-target-group --name ppq-enclave-tls --protocol TCP --port 443 --vpc-id "$VPC" \
  --target-type instance --health-check-protocol HTTPS --health-check-port 443 --health-check-path /health \
  --matcher HttpCode=200 --health-check-interval-seconds 10 --healthy-threshold-count 2 --unhealthy-threshold-count 2 \
  --tags Key=Name,Value=ppq-enclave-tls "${P[@]}" --query 'TargetGroups[0].TargetGroupArn' --output text)
echo "$TG"
aws elbv2 modify-target-group-attributes --target-group-arn "$TG" \
  --attributes Key=preserve_client_ip.enabled,Value=false Key=deregistration_delay.timeout_seconds,Value=60 "${P[@]}" >/dev/null

echo "== NLB: internet-facing, all six public subnets, cross-zone"
LB=$(aws elbv2 create-load-balancer --name ppq-enclave --type network --scheme internet-facing --ip-address-type ipv4 \
  --subnets $SUBNETS --tags Key=Name,Value=ppq-enclave "${P[@]}" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
echo "$LB"
aws elbv2 modify-load-balancer-attributes --load-balancer-arn "$LB" \
  --attributes Key=load_balancing.cross_zone.enabled,Value=true "${P[@]}" >/dev/null
aws elbv2 create-listener --load-balancer-arn "$LB" --protocol TCP --port 443 \
  --default-actions Type=forward,TargetGroupArn="$TG" "${P[@]}" --query 'Listeners[0].ListenerArn' --output text

echo "== register the build host"
aws elbv2 register-targets --target-group-arn "$TG" --targets Id=$I,Port=443 "${P[@]}"
aws elbv2 wait load-balancer-available --load-balancer-arns "$LB" "${P[@]}"
DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$LB" "${P[@]}" --query 'LoadBalancers[0].DNSName' --output text)
for i in $(seq 1 30); do
  H=$(aws elbv2 describe-target-health --target-group-arn "$TG" "${P[@]}" --query 'TargetHealthDescriptions[0].TargetHealth.State' --output text)
  echo "[$i] target: $H"; [ "$H" = "healthy" ] && break; sleep 10
done

echo "== through the NLB, with SNI, DNS untouched"
IP=$(dig +short "$DNS" | head -1)
for i in 1 2 3 4 5 6; do
  curl -s --max-time 15 --resolve "enclave.ppq.ai:443:$IP" https://enclave.ppq.ai/health \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('worker', d.get('worker'), 'of', d.get('workers'), d.get('hpke_identity'), (d.get('hpke_public_key') or '')[:12])"
done
echo "TG=$TG"; echo "LB=$LB"; echo "NLB_DNS=$DNS"
