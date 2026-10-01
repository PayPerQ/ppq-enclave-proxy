# Operating the enclave fleet

The runbook half of what used to be the README: how the boxes, load
balancers, nginx arms and certificates are put together and kept running.
None of this changes the privacy claim; [README.md](README.md) states the
claim and how to verify it, and this file is for whoever has to keep the
thing serving.

## Hosts and ports

Every box runs the same image. On each box:

| Port | Listener | Carries |
|---|---|---|
| `:443` (nginx, `ssl_preread`) | SNI split: `enclave.ppq.ai` → socat → vsock `:8443` | the web app's chat path; bare ClientHello into the enclave |
| `:8445` (nginx, `proxy_protocol on`) | socat on `/run/ppq/pp.sock` → vsock `:8445` | the `api.ppq.ai` path; a PROXY v1 header, then the ClientHello |
| `127.0.0.1:8444` (nginx, host TLS) | the **rollback arm** | nothing, unless the map in `nginx-sni-split.conf` is flipped |
| `:8443` host forwarder | reachable from one operator IP | `client/verify.mjs` against the enclave's own server name |

Nothing on the host holds a key for any public name. The two nginx arms
forward TCP; socat bridges to vsock; TLS ends in the enclave.

### The api arm (`:8445`, PROXY protocol)

`api.ppq.ai` needs the client's address (horse-power rate-limits, geo-blocks
and logs by it), and nothing on the path can put it in an HTTP header because
nothing on the path sees HTTP. So the api path is a second port end to end:
its own NLB with client-IP preservation **on** → nginx `:8445` with
`proxy_protocol on` → socat on the unix socket `/run/ppq/pp.sock` → vsock
`:8445` → `proxyListener.mjs`, which reads exactly the header's bytes and hands
the connection, ClientHello still buffered, to the same TLS server that serves
`:8443`.

nginx writes the v1 text line, and that is the only header the enclave
receives on this path. The api NLB preserves client IPs at the TCP level and
does **not** have `proxy_protocol_v2` enabled on its target group, because the
nginx arm does not parse an inbound header and would forward it as a second
one. The enclave also parses v2, for a future no-nginx variant.

**Trust.** A PROXY header is an unauthenticated claim, so only nginx may make
one: the socat that feeds vsock `:8445` listens on a unix socket owned
`root:nginx`, mode 660, in a 750 directory, so root and nginx's workers are
the only local principals that can write to it. A loopback TCP port would be
open to every local user. `/health` reports `proxy_protocol: true` on an
enclave listening this way.

**Installing it.** `scripts/install-pp-arm.sh` puts the arm on a box, inside
production's existing `stream {}` block (`nginx-pp-arm-server.conf`) or as its
own block on a box that has none, such as the dev box (`nginx-pp-arm.conf`).
`--uninstall` reverses it. It is applied to the build host, so the next AMI
carries it. `scripts/pp-forwarder.sh` is the host-side socat; `run-host.sh`
starts it when `inbound_pp_socket` is set.

**Runtime switches** live in SSM `/ppq-enclave/fleet-config` and are read by
both `scripts/fleet/boot-enclave.sh` and the cutover workflow, so the fleet
and the build host cannot disagree:

| Key | Value | Effect |
|---|---|---|
| `inbound_pp_socket` | `/run/ppq/pp.sock` | `run-host.sh` starts the forwarder |
| `passthrough_host` | `backend.ppq.ai` | arms the transparent proxy in the init blob |
| `acme_domain` | `enclave-direct.ppq.ai,enclave.ppq.ai,api.ppq.ai` | the names on the certificate |

Both switches empty means the arm is installed but dark, which is how a box
behaves until a flip is being prepared.

### The 443 arm

`enclave.ppq.ai` keeps its NLB with client-IP preservation **off**, its nginx
arm with no `proxy_protocol`, and its bare ClientHello into `:8443`.
`proxy_protocol` is per nginx server block, not per SNI, which is why the api
path is a different port rather than a flag. Preservation is off because of a
documented AWS failure mode (a hairpin duplicates the 4-tuple and the
connection stalls); the write-up is in `scripts/fleet/create-nlb.sh`.

### The rollback arm (`127.0.0.1:8444`)

nginx keeps a host-terminated server with the old certbot certificate for
`enclave.ppq.ai`. One map line in `scripts/nginx-sni-split.conf` and a reload
put the public name back on it. It is the emergency exit if in-enclave TLS
ever has to be backed out; while it is in use the privacy property does not
hold, and the drift check reports it (served SPKI ≠ attested SPKI).

**Its certificate expires on 2026-10-13.** After that the exit serves an
expired certificate and is not a usable rollback. Either renew it with certbot
before then or accept that the rollback is a rebuild.

## Load balancers

| NLB | Target group | Port | Client IP | Health check |
|---|---|---|---|---|
| `ppq-enclave` (`enclave.ppq.ai`) | `ppq-enclave-tls` | 8443 | preservation off | TCP |
| `ppq-api` (`api.ppq.ai`) | created by `create-api-nlb.sh` | 8445 | preservation on, PROXY v2 off | HTTPS `/health` on 8445, so the whole arm is what is checked |

`scripts/fleet/create-api-nlb.sh` creates the api NLB and target group.
Attaching the group to the autoscaling group is a separate, opt-in step
(`ATTACH_ASG=1 bash scripts/fleet/create-api-nlb.sh`) that registers every
instance the ASG currently has and attaches only once all of them are healthy
on 8445, refusing otherwise. The ASG's health check is ELB, an instance is
unhealthy when **any** attached group says so, and a box whose AMI lacks the
arm fails this group's check, so attaching too early makes the ASG replace
every box about every six minutes (observed 2026-09-18). Detach before any
refresh onto an AMI without the arm.

The api NLB carries roughly 95% of new connections; `enclave.ppq.ai` the
rest.

## Autoscaling

The group is `ppq-enclave-fleet`. `scripts/fleet/configure-autoscaling.sh`
applies the policy and records why: it scales on TCP connections per healthy
box across **both** load balancers, target 150. Until 2026-09-24 it scaled on
the `enclave.ppq.ai` balancer's total alone, which was about 5% of the traffic
and, being a total, never fell as boxes were added, so the fleet could only
sit at its minimum or ratchet to its maximum.

Boxes launch only in the five zones that offer `c6i.2xlarge` (`us-east-1e`
does not). A box being removed drains for 300 s, past the pass-through's 240 s
wait, which makes each replacement in a refresh take roughly ten minutes.

The group's minimum and maximum are set in the console, not in this repo.

Still to do: scale on each box's own open-stream count (`/health` reports it
per worker, so it needs a per-box total), hold a terminating box until its
streams finish, and ship host journals to CloudWatch Logs (the host role can
already write to `/ppq-enclave/*` log groups).

## Scaling alerts

`scripts/fleet/configure-scaling-alerts.sh` creates an EventBridge rule and a
small Lambda (`scripts/fleet/scaling-alerts/index.mjs`) that posts one line to
the enclave alerts Slack channel for every scale-out, scale-in, health-check
replacement and failed launch or termination. The webhook lives in SSM under
`/ppq-ops/`, which the untrusted hosts cannot read once
`scope-host-parameter-access.sh` has confined each host role to its own path.
Instance-refresh rolls that succeed stay silent, because every release rolls
the fleet on purpose and its workflow reports it. Store the webhook, then run
`configure-scaling-alerts.sh --test` once.

## Certificates

### The enclave's certificate

One certificate, three names: `enclave-direct.ppq.ai`, `enclave.ppq.ai`,
`api.ppq.ai`. The private key was generated in an enclave and is distributed
only inside the sealed store blob. Renewal runs from CI
(`.github/workflows/enclave-renew-cert.yml`, daily at 06:40 UTC) against the
build host, which is the single renewal authority:

1. CI asks the authority enclave for a fresh key and CSR (`POST /acme/csr`).
2. CI proves control of the names to Let's Encrypt over DNS-01 with the
   GoDaddy token (`scripts/renew-cert-dns01.mjs`, `scripts/lib/dns01.mjs`).
3. CI hands the issued chain back (`POST /acme/install`); the enclave verifies
   it against the pinned ISRG roots (`enclave/src/trustRoots.mjs`) before
   installing it and re-sealing the store.
4. The fleet is rolled so every box boots from the new blob.

The two ACME endpoints answer 404 unless `ACME_RENEWAL_MODE` is `dns01-ci`,
the box is the authority, and the CI token matches.

### The Azure standby's certificate

When `api.ppq.ai` terminates on the enclave, the App Service `ppq-backend-us`
stays behind it as the hot standby for the name, and its App Service managed
certificate stops renewing, since Azure re-validates the hostname through the
CNAME that now points elsewhere. The enclave's certificate cannot be handed
over (its key never leaves the enclave, and Azure must hold the key to
terminate TLS). So `.github/workflows/azure-api-cert.yml`
(`scripts/renew-azure-cert-dns01.mjs`) orders a Let's Encrypt certificate for
`api.ppq.ai` alone, with its own key generated on the runner and discarded
after the run, proves the name over the same DNS-01 flow, verifies the chain
against the same pinned roots, and uploads it as a PFX bound to the app's
hostname over OIDC (`Website Contributor` on the one resource group, no stored
Azure credential). Without the three `AZURE_*` secrets a production run is
skipped with a notice rather than failing.

The two renewal jobs share one concurrency group (`acme-dns01-godaddy`), so
they never touch `_acme-challenge` records at once. The drift check reads the
certificate the standby serves (SNI `api.ppq.ai`, by the app's own hostname,
independent of where the public name points) and treats fewer than 20 days
remaining as drift.

## Releasing an image

Every change under `enclave/src`, `enclave/boot.sh` or `enclave/Dockerfile` is
a new measurement. The sequence is in the README's
[Rotation](README.md#rotation-how-a-new-image-reaches-production) table; the
operational notes are:

- The cutover **refuses to run** unless the incoming `PCR0` is already in
  `accepted_pcr0` alongside the current one. Do the pre-accept PR first.
- After the swap it delivers Bedrock credentials, verifies the measurement,
  prunes the KMS allow-list to {running, previous}, and smoke-tests before
  dispatching the fleet refresh.
- The fleet refresh refuses to bake an AMI if the EIF on disk differs from the
  running enclave. It rolls the group with `MaxHealthyPercentage` 150.
- Publish promptly after a cutover: the npm proxy pins `current.pcr0` only, so
  between cutover and publish its Nitro path for non-private models fails
  closed.
- Rotating `PCR0` invalidates every open browser tab's pin until it reloads;
  the web app accepts the previous measurement during a rollover, so keep the
  outgoing entry in `accepted_pcr0` until the fleet has rolled, then prune it.

## Bedrock credentials

Short-lived STS credentials for the Bedrock direct path are delivered by the
host over the persistent vsock `:7001` channel (`scripts/send-creds.sh`), on a
systemd timer every **20 minutes** (`scripts/systemd/ppq-bedrock-creds.timer`).
They are KMS-enveloped under the attestation-gated CMK when possible and
plaintext otherwise; an expiration is required either way. The cluster primary
relays each blob and every worker decrypts and applies it itself.

## The dev enclave

A second Nitro host with its own hostname (`enclave-dev.ppq.ai`) and no access
to any production secret, for changes to `boot.sh` and the handshake path that
unit tests cannot exercise. See [DEV-ENCLAVE.md](DEV-ENCLAVE.md). Stop it when
you are done; it bills by the hour.
