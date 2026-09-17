# The dev enclave

A second Nitro host for testing enclave changes **without touching production**.

## Why it exists

Three things had no safe test before it:

**`boot.sh` and the TLS handshake path.** A mistake in either does not degrade —
it takes the enclave down, and there is **no rollback EIF** (the build directory
holds one image and each build overwrites it), so recovery is a ~25 minute
rebuild. On 2026-09-03 a `createSecureContext` symbol was nearly shipped
unimported *into the SNI callback*; `node --check` passes on that, and it would
have broken every handshake.

**ACME.** ~600 lines of RFC 8555 client that had never spoken to a CA, because
the challenge is a TLS handshake to the enclave itself and cannot be exercised
outside one.

**The cutover workflow.** Every change to it — the accept-list guard, the atomic
re-pin, the failure reporter — had only ever been validated by running it against
production and watching.

## What it is

| | |
|---|---|
| Instance | `i-052589172022c8c88` (`ppq-enclave-dev`), c6i.xlarge, us-east-1d |
| Hostname | `enclave-dev.ppq.ai` |
| Security group | `ppq-enclave-dev-sg` — **443 open**, because ACME TLS-ALPN-01 validation must reach it from Let's Encrypt |
| IAM role | `ppq-enclave-dev-host` |
| Allocation | 2 vCPU / 3072 MiB — identical to production, so an image that fits there fits here |

**No nginx.** The inbound forwarder sits directly on `:443`. That is not a
shortcut: it is the phase-3 end state of #52 (no L7 proxy in the byte path), so
dev exercises the topology production is moving toward, and it is what makes
TLS-ALPN-01 reachable without an SNI split.

## The isolation property, and its limit

The dev role **cannot read any production secret**. This is enforced, not
conventional:

| | prod `ppq-enclave-host` | dev `ppq-enclave-dev-host` |
|---|---|---|
| `kms:Decrypt` | **unconditioned** — can decrypt under the prod CMK | only `kms:ViaService = ssm.us-east-1.amazonaws.com` |
| SSM parameters | `/ppq-enclave/*` | `/ppq-enclave-dev/*` only |

So a dev enclave cannot decrypt the production OpenRouter, Anthropic, Fireworks
or Vertex keys even if asked to, and a compromise of the dev box yields nothing
production-side.

**The limit worth knowing:** a dev enclave has a different PCR0, so it can never
satisfy the prod CMK's attestation condition. It therefore runs on plaintext dev
keys, which means **the attestation-gated KMS decrypt path is still only ever
exercised in production.** That is the most security-critical step of boot, and
the dev box does not cover it. Do not assume otherwise.

## Cost

About $0.17/hour running; stopped it is just the 40 GB gp3 root volume, a few
dollars a month. **Stop it when you are done** — it is not needed between
sessions.

```bash
aws ec2 stop-instances  --instance-ids i-052589172022c8c88 --profile ppq-enclave
aws ec2 start-instances --instance-ids i-052589172022c8c88 --profile ppq-enclave
```

The public IP changes on restart, so `enclave-dev.ppq.ai` must be re-pointed:

```bash
IP=$(aws ec2 describe-instances --instance-ids i-052589172022c8c88 --profile ppq-enclave \
      --query 'Reservations[].Instances[].PublicIpAddress' --output text)
curl -s -X PUT -H "Authorization: Bearer $GODADDY_API_TOKEN" -H 'Content-Type: application/json' \
  https://api.godaddy.com/v1/domains/ppq.ai/records/A/enclave-dev -d "[{\"data\":\"$IP\",\"ttl\":600}]"
```

## Using it

Everything runs through SSM; there is no SSH key. **Use the same scripts as
production with different env — never a forked copy, or you are testing the
wrong thing.**

### Before you start

These are not provisioned, and each one costs a confusing failure if skipped:

- **No dev secrets exist.** `/ppq-enclave-dev/*` is empty. For an OpenRouter
  key, mint a throwaway with a spend limit through the provisioning API
  (`POST https://openrouter.ai/api/v1/keys` with `{"name": "...", "limit": 3}`)
  and delete it when done.
- **The dev backend must know the settle secret.** Set `ENCLAVE_SETTLE_SECRET` on
  the dev backend to the value you pass to `send-init.sh` **before** sending
  traffic. The enclave treats a settle `401` as permanent and drops it, so
  requests sent earlier are never recorded and cannot be replayed.
- **`SETTLE_HOST` is the dev backend's default hostname**, which is regional:
  `az webapp show -g ppq-backend-dev -n ppq-backend-dev --query defaultHostName -o tsv`.
  The short `<app>.azurewebsites.net` form does not resolve.
- **The dev backend has its own database.** A credit id that exists for local
  development may not exist there (`401 Invalid credit ID`). Use a designated
  test account that does, never a real user's.

```bash
DEV=i-052589172022c8c88
SETTLE_HOST=$(az webapp show -g ppq-backend-dev -n ppq-backend-dev --query defaultHostName -o tsv)

# 1. sync to the commit under test. SSM runs as root with no HOME; git needs one,
#    and the checkout is owned by ec2-user.
aws ssm send-command --instance-ids $DEV --document-name AWS-RunShellScript --profile ppq-enclave \
  --parameters 'commands=["export HOME=/root","git config --global --add safe.directory /home/ec2-user/ppq-enclave-proxy","cd /home/ec2-user/ppq-enclave-proxy && sudo -u ec2-user git fetch origin && sudo -u ec2-user git checkout -q <branch-or-sha>"]'

# 2. build (~5 min cached, ~25 cold). The nitro-cli E51 gotcha applies here too:
#    these two vars are load-bearing.
aws ssm send-command --instance-ids $DEV --document-name AWS-RunShellScript --profile ppq-enclave \
  --timeout-seconds 2400 --parameters 'commands=["cd /home/ec2-user/ppq-enclave-proxy && mkdir -p /home/ec2-user/nitro-artifacts && HOME=/root NITRO_CLI_ARTIFACTS=/home/ec2-user/nitro-artifacts SOURCE_DATE_EPOCH=1704067200 bash scripts/build-enclave.sh 2>&1 | tail -40"]'

# 3. run. INBOUND_LISTEN_PORT=443 is the dev-only difference. STORE_S3="" stops
#    the sealed-store listener publishing to the PRODUCTION bucket. run-host.sh
#    exits non-zero if any outbound vsock-proxy fails to start (#173).
aws ssm send-command --instance-ids $DEV --document-name AWS-RunShellScript --profile ppq-enclave \
  --timeout-seconds 900 --parameters "commands=[\"cd /home/ec2-user/ppq-enclave-proxy && HOME=/root NITRO_CLI_ARTIFACTS=/home/ec2-user/nitro-artifacts INBOUND_LISTEN_PORT=443 STORE_S3= SETTLE_HOST=$SETTLE_HOST REGION=us-east-1 ENCLAVE_CID=16 EIF=/home/ec2-user/ppq-enclave-proxy/build/ppq-enclave-proxy.eif bash scripts/run-host.sh\"]"

# 4. init blob. Dev keys only. STORE_S3_PULL="" stops the pull of the PRODUCTION
#    sealed store (STORE_S3 does not control the pull; see send-init.sh).
#    ACME_DOMAIN triggers an order; STAGING by default. Never point a dev box at
#    the production ACME directory: the 5-duplicate-certificates-per-week ceiling
#    is per registered domain and a burn is shared with production.
aws ssm send-command --instance-ids $DEV --document-name AWS-RunShellScript --profile ppq-enclave \
  --parameters "commands=[\"cd /home/ec2-user/ppq-enclave-proxy && STORE_S3_PULL= ENCLAVE_WORKERS=2 ENCLAVE_SETTLE_SECRET=<dev-secret> OPENROUTER_KEY_PLAINTEXT=<throwaway-key> SETTLE_HOST=$SETTLE_HOST REGION=us-east-1 ENCLAVE_CID=16 bash scripts/send-init.sh\"]"
```

### Checking it

- `curl -sk https://enclave-dev.ppq.ai/health` should show `keyLoaded: true` and
  one entry per worker.
- **Every chat returns `502 {"error":"authorization failed"}`:** the enclave
  cannot reach the backend. Check the settle proxy is running
  (`pgrep -f "vsock-proxy 9444 "`) and `SETTLE_HOST` resolves from the box.
- To drive real requests, use the frontend's
  `utils/crypto/nitroSecureFetch.mjs` from Node with `expectedPcr0` set to the
  build under test. The dev certificate is not publicly trusted, so the Node
  process needs `NODE_TLS_REJECT_UNAUTHORIZED=0`; the EHBP seal still protects
  the body.

## Rules

1. **Same scripts, different env.** A forked `run-host.sh` tests something that
   is not production. `INBOUND_LISTEN_PORT` exists so the one real difference is
   expressed as configuration.
2. **Staging ACME only.** Let's Encrypt's duplicate-certificate limit is per
   registered domain, so `ppq.ai` is shared with production. A dev burn is a
   production outage with a week-long fuse.
3. **No production secrets.** The IAM role prevents it; do not work around that
   by pasting keys into an init blob.
4. **Stop it when done.**
5. **A green dev run is not a green production run.** Different PCR0, plaintext
   keys, no KMS path, no real traffic. It raises confidence; it does not
   substitute for verifying the cutover.

## Related

- `attestation/PUBLISHED_PCR.md` — production measurements
- `scripts/run-host.sh` — shared, env-driven
- #52 (TLS in enclave), #58 (routing receipts)
