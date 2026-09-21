# ppq-enclave-proxy

A confidential-computing proxy for PayPerQ chat completions. It runs inside an
**AWS Nitro Enclave** so that **PayPerQ cannot observe the content** of user
queries or model responses. Clients connect to `https://enclave.ppq.ai`; the
TLS connection terminates *inside* the enclave, the enclave calls the model
provider, and PayPerQ's backend (horse-power) is never on the byte path — it
receives only **billing metadata** (token counts, cost, credit id).

This repository is **public and its builds are reproducible on purpose**: the
privacy claim only holds if anyone can rebuild this exact source, reproduce the
enclave measurement (`PCR0`), and verify that the running enclaves match. See
[Reproducible builds](#reproducible-builds) and [REPRODUCE.md](REPRODUCE.md).

Current published measurement: [`attestation/published-pcr.json`](attestation/published-pcr.json)
(history in [`attestation/PUBLISHED_PCR.md`](attestation/PUBLISHED_PCR.md)).

## Threat model

**What this protects.** PayPerQ — the parent EC2 instances, their operators, the
backend, databases and logs — cannot read the **content** of a request or a
response. The client's TLS session ends inside the enclave, with a
browser-trusted Let's Encrypt certificate whose private key was generated in an
enclave and has never existed outside one. The parent forwards encrypted bytes
and holds no key that could open them.

**What PayPerQ still sees.** Metadata, and no claim of unlinkability is made:

- The enclave settles every request to horse-power with the credit id, model,
  token counts and cost. PayPerQ can therefore tie an account to a timestamp,
  a model and a response size. It cannot read the text.
- The parent instance sees the TLS server name (SNI is cleartext in every TLS
  handshake), connection timing and byte counts. On `enclave.ppq.ai` it logs
  the load balancer's private address rather than the client's IP; the load
  balancer itself, being AWS infrastructure PayPerQ operates, does see client
  IPs. Do not read "the parent is blind" as "PayPerQ cannot learn your IP".

**What this does NOT protect.** The upstream model provider (OpenRouter,
Anthropic, Fireworks, Google Vertex, AWS Bedrock) receives plaintext — it must,
to run inference. The guarantee is *"PayPerQ is blind,"* not end-to-end secrecy
from every party. For models that run fully inside an enclave, see PayPerQ's
Tinfoil private models instead.

**The guarantee is only meaningful if the client verifies attestation** and
pins the published `PCR0` before sending anything. A client that skips
verification is trusting PayPerQ's word, which is exactly what this design
exists to make unnecessary. See [Verifying the enclave](#verifying-the-enclave).

## Architecture

```
client                    AWS edge + EC2 parent (untrusted)                     ENCLAVE (attested)
  │                                                                          ┌──────────────────────────┐
  │  TLS ──▶ NLB (TCP passthrough) ──▶ nginx :443 ──▶ socat :8443 ──vsock──▶│ terminates the client's  │
  │          enclave.ppq.ai            SNI preread     raw bytes             │ TLS (Let's Encrypt key   │
  │          no TLS termination        no key, no      no key                │ generated in-enclave)    │
  │                                    termination                           │ opens the EHBP seal if   │
  │                                                                          │   present                │
  │                                                                          │ eligibility + routing    │
  │                                                                          │ provider keys via        │
  │                                                                          │   attestation-gated KMS  │
  │                                                                          │ calls the upstream ──────┼──▶ provider
  │                                                                          │ extracts usage/cost      │
  │                                                                          │ signs a routing receipt  │
  │                                                                          │ POST /enclave/settle ────┼──▶ horse-power
  │                                                                          └──────────────────────────┘    (metadata only)
```

**Nothing on the parent can read the stream.** The load balancer is a Network
Load Balancer with a plain TCP listener; nginx runs `ssl_preread` and forwards
by server name without terminating; socat bridges TCP to the enclave's vsock.
None of them holds a private key for `enclave.ppq.ai`. The certificate the
client is served is the one the NSM-signed attestation commits to — confirm it
in ten seconds:

```bash
# the SPKI hash of the certificate you were actually served
echo | openssl s_client -connect enclave.ppq.ai:443 -servername enclave.ppq.ai 2>/dev/null \
  | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256

# the value the NSM-signed attestation document commits to — these MUST match
curl -s "https://enclave.ppq.ai/attestation?nonce=$(openssl rand -hex 16)" | jq -r .cert_spki_sha256
```

If they ever differ, something on the path is terminating TLS, and the check in
`scripts/check-live-attestation.mjs` (run daily from CI against every box) is
designed to catch precisely that.

### PROXY protocol on the api port

`api.ppq.ai` needs the client's address — horse-power rate-limits, geo-blocks
and logs by it — and nothing on the path above can put it in a header,
because nothing on that path can see HTTP: the load balancer and nginx forward
TCP, and TLS ends in the enclave. The one mechanism that works *below* TLS is
[PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt):
the last hop that knows the address prepends a small header to the
connection, and the enclave reads it before it starts the handshake.

So the api path is a **second port, end to end**: its own NLB with client-IP
preservation on → nginx `:8445` with `proxy_protocol on` → a socat on the unix
socket `/run/ppq/pp.sock` → vsock `:8445` → `proxyListener.mjs` inside the
enclave, which reads exactly the header's bytes, records the address as
`req.socket.clientIp`, and hands the connection — ClientHello still buffered —
to the same TLS server that serves `:8443`. From there the request is handled
identically; the only difference is that the trace's `client_ip` is present
and that the authorize call and every proxied route carry the MAC'd
`x-ppq-client-ip` pair that horse-power verifies (keyed with the settle
secret, minute-bounded).

nginx writes the v1 text line, and that is the only header the enclave
receives on this path: the api NLB preserves client IPs at the TCP level and
does **not** have its own `proxy_protocol_v2` target-group attribute enabled,
because the nginx arm does not parse an inbound header and would forward it
as a second one. The enclave also parses v2, for a future no-nginx variant
(NLB v2 straight into socat).

**How it reaches a box.** `scripts/fleet/create-api-nlb.sh` creates the api
NLB and its target group (port 8445, preservation on, PROXY v2 off, health
check HTTPS `/health` on 8445 so the whole arm is what is checked). Attaching
the group to the autoscaling group is a separate, opt-in step
(`ATTACH_ASG=1 bash scripts/fleet/create-api-nlb.sh`), which registers every
instance the ASG currently has and attaches only once all of them are healthy
on 8445, refusing otherwise: the ASG's health check is ELB, an instance is unhealthy
when ANY attached group says so, and a box whose AMI lacks the arm fails
this group's 8445 check, so attaching too early makes the ASG replace every
box about every six minutes (2026-09-18). Detach before any refresh onto an
AMI without the arm. `scripts/install-pp-arm.sh`
puts the nginx arm on a box (inside production's existing stream block, or
as its own on the dev box) and is applied to the build host, so the next
AMI carries it. The two runtime switches live in SSM `/ppq-enclave/fleet-config`:
`inbound_pp_socket` (`/run/ppq/pp.sock`) starts `scripts/pp-forwarder.sh`
under `run-host.sh`, and `passthrough_host` (`backend.ppq.ai`) arms the
pass-through in the init blob. `boot-enclave.sh` and the cutover workflow
both read them, so the fleet and the build host cannot disagree; both empty
means the arm is installed but dark, which is how a box behaves until the
flip is being prepared.

**The 443 path is unchanged.** `enclave.ppq.ai` keeps its NLB with
preservation off (the hairpin failure mode in `scripts/fleet/create-nlb.sh`
still applies to it), its nginx arm with no `proxy_protocol`, and its bare
ClientHello into `:8443`. `proxy_protocol` is per nginx server block, not per
SNI, which is precisely why it is a different port rather than a flag.

**Trust.** A PROXY header is an unauthenticated claim, so the design is that
only nginx can make one. The host-side socat that feeds vsock `:8445` listens
on a unix socket owned `root:nginx`, mode 660, in a 750 directory, so root
and nginx's workers are the only local principals that can write to it
(a loopback TCP port would be open to every local user); nginx writes the
address it accepted the connection from; and the enclave sets `clientIp` from
the header alone — never from `x-forwarded-for` or any other header a client
can send (`passthrough.mjs` strips every inbound `x-ppq-client-ip*`). Public
`:8445` carries no header; it is where the claim is *made*, by the box's own
nginx. `/health` reports `proxy_protocol: true` on an enclave that listens
this way.

**What the client address is, and is not.** It is asserted by the host —
nginx, behind the load balancer — exactly like the load balancer's own view
of the peer. Its integrity therefore rests on the host; it is not part of
the privacy claim, and the [threat model](#threat-model) already states that
the parent sees IPs and metadata. horse-power uses it for the decisions it
already makes from Azure's `X-Client-IP` today: sanctions screening, per-IP
limits, support identity. There is no trusted edge that could sign the
address, so a cryptographic assertion of it is out of scope; the MAC on
`x-ppq-client-ip` binds only the value the enclave saw, so that nothing
between the enclave and horse-power can substitute another.

### The two hostnames

| Hostname | What it is | Who uses it |
|---|---|---|
| `enclave.ppq.ai` | The NLB in front of every enclave box | Everyone: the web app, the npm package, API clients |
| `enclave-direct.ppq.ai` | The build host's own Elastic IP, no load balancer | Certificate renewal from CI, the reference verifier, operators |

Both names are on one certificate and both terminate inside the enclave. The
difference is only *which box* you reach: the direct name always lands on the
build host, which is the single **renewal authority** (see below); the public
name lands on whichever box the load balancer picks. Every box presents the
same `PCR0`, the same HPKE key and the same certificate, so a client never
needs to know or care which one answered.

The host's `:8443` forwarder is also reachable directly from one operator IP
for `client/verify.mjs`; it is not a production path.

### EHBP — why a second layer still exists

Requests may additionally carry an HPKE-sealed body (EHBP, header
`Ehbp-Encapsulated-Key`), sealed to the enclave's HPKE public key. With TLS
already ending in the enclave this looks redundant; it is not, for one class of
client: **browser JavaScript cannot read its own TLS peer certificate**, so a
page can verify an attestation perfectly and still have nothing to compare its
connection against. A malicious host could terminate the browser's TLS and
proxy the attestation through. EHBP closes that: the browser verifies the
attestation, takes the HPKE key *from inside the signed document*, and seals to
it. This is what the web app does (`client/nitro-secure-fetch.mjs`).

SDK and CLI clients that *can* inspect the certificate get the same property
from attested TLS alone. Both paths remain, and `/attestation` commits to both
keys (see the table under [Verifying the enclave](#verifying-the-enclave)).

### Outbound, keys, billing

- **Outbound:** the enclave reaches every upstream, KMS, Let's Encrypt and
  horse-power through host-side `vsock-proxy` hops. TLS to each is validated
  inside the enclave against the real hostname; the proxy forwards bytes and
  can only choose *whether* a connection happens, never read it. The allow-list
  is in `scripts/run-host.sh`.
- **Key custody:** provider API keys are KMS-encrypted and `kms:Decrypt` is
  gated on `kms:RecipientAttestation:PCR0`, so KMS releases them **only** to an
  enclave whose measurement is on the published allow-list. Operators cannot
  extract them. `/health` reports per provider under `key_sources` which mode a
  running enclave actually used (`kms`, or the fallback described under
  [Known gaps](#known-gaps--read-before-quoting-the-privacy-claim)).
- **Billing:** the enclave never writes to a database. It reports token counts
  and cost to horse-power `POST /enclave/settle` (idempotent by `request_id`),
  which applies the margin and debits credits. Nothing in that call is content.

## Routes the enclave does not serve: the transparent proxy

When a hostname that carries more than chat terminates here (api.ppq.ai), the
request router runs a thin check first: is this `method + path` one the enclave
serves itself (`POST /chat/completions`, `POST /v1/chat/completions`, `GET /health`,
`GET /attestation`, `POST /acme/csr`, `POST /acme/install`, and OPTIONS on those
paths)? If not,
`passthrough.mjs` forwards it to horse-power over the settle tunnel, verbatim
and unbuffered, and relays the answer verbatim — including `Upgrade` for the
transcription WebSocket. The check runs per request, not per connection, so a
keep-alive connection can carry a proxied `/v1/models` and then an in-enclave
chat call without the chat ever leaving the enclave.

This is a compatibility shim, not a privacy claim: those routes are served by
horse-power exactly as before and merely transit the enclave. Every inbound
header that could claim a client address is stripped; the enclave adds its own
MAC'd `x-ppq-client-ip` pair when the connection arrived on the PROXY-protocol
port (see [PROXY protocol on the api port](#proxy-protocol-on-the-api-port)).
Enabled by `passthrough_host` in the init blob (`PASSTHROUGH_HOST` to
`send-init.sh`), and even then only for connections that arrived through the
PROXY-protocol port with a client address in the header (the api path;
`proxyListener.mjs` marks them `viaProxyProtocol`; an addressless `UNKNOWN` or
`LOCAL` header completes the handshake but is not proxied). On the plain port, enclave.ppq.ai's, unknown routes stay
404 whatever the blob says: configuring a passthrough host never widens what
that hostname serves, and no proxied request leaves without a client address
horse-power can rate-limit and geo-block by.

## The fleet — how this scales without weakening the claim

`enclave.ppq.ai` is served by the build host plus an autoscaling group of
identical boxes (`scripts/fleet/`). Three things had to become shared for a
fleet to be possible at all, and each is shared *inside* the trust boundary:

1. **One measurement.** `PCR0` is a property of the image, not the machine. A
   fleet of boxes booted from one image publishes one hash, and the daily
   drift check visits every healthy box to confirm they all present it.
2. **One EHBP identity.** The HPKE key pair lives in the sealed store — a blob
   encrypted under the attestation-gated CMK, so the parent that stores and
   copies it holds ciphertext it cannot open. Every box unseals the same
   identity at boot and `/health` reports `hpke_identity: store` when it did.
   A box that could not load a stored identity serves a fresh key and reports
   `rejected` rather than silently overwriting the shared one.
3. **One certificate.** The private key was generated in an enclave and is
   distributed only inside that same sealed blob. Renewal runs from CI
   (`enclave-renew-cert.yml`, daily) with the key never leaving the enclave:
   the authority enclave produces a fresh key and CSR, CI proves control of the
   names to Let's Encrypt over DNS-01, and hands the issued chain back to the
   enclave, which verifies it against pinned ISRG roots before installing it
   and re-sealing the store. The fleet is then rolled so every box boots from
   the new blob. Exactly one box — the build host — is the renewal authority;
   every other box is a consumer.

**The Azure standby's certificate.** When api.ppq.ai terminates on the
enclave, the App Service `ppq-backend-us` stays behind it as the hot standby
for the name — and its App Service *managed* certificate stops renewing, since
Azure re-validates the hostname through the CNAME that now points elsewhere.
The enclave's certificate cannot be handed over: its key never leaves the
enclave, and Azure must hold the key to terminate TLS. So a second daily job,
`azure-api-cert.yml` (`scripts/renew-azure-cert-dns01.mjs`), orders a
Let's Encrypt certificate for api.ppq.ai alone with its **own key generated on
the runner and discarded after the run**, proves the name over DNS-01 with the
same GoDaddy token and the same order flow (shared verbatim in
`scripts/lib/dns01.mjs`), verifies the chain against the same pinned ISRG roots,
and uploads it as a PFX bound to the app's `api.ppq.ai` hostname over OIDC
(`Website Contributor` on the one resource group, no stored Azure credential).
The two jobs are siblings — same proof, same CA, separate keys and separate
SAN sets — and they share one concurrency group (`acme-dns01-godaddy`), so they
never touch `_acme-challenge` records at once whatever the schedule does. The drift check reads the certificate
the standby serves (by the app's own hostname, SNI `api.ppq.ai`, independent of
where the public name points) and treats fewer than 20 days remaining as
drift, so a stalled renewal reaches the canonical issue like any other.

Inside each enclave a Node `cluster` runs several workers behind one port; the
primary alone owns the store, the identity, ACME and credential delivery, so
adding workers adds capacity without adding writers. `/health` reports
`workers` and which `worker` answered.

The load balancer is deliberately configured *not* to preserve client IPs
toward the boxes; the reason is a documented AWS failure mode and is written up
in `scripts/fleet/create-nlb.sh`.

## Rotation — how a new image reaches production

Every change to the enclave is a new measurement, so shipping is a trust event
and is done by CI, in the open, in this order:

| Workflow | What it does |
|---|---|
| `enclave-build.yml` | Reproducible build; emits `PCR.json` and a Sigstore attestation over it |
| *pre-accept* (a PR to `published-pcr.json`) | Adds the incoming `PCR0` to `accepted_pcr0` **alongside** the current one, so a client whose bundle predates the swap keeps accepting the enclave |
| `enclave-cutover.yml` | Adds the new `PCR0` to the KMS allow-list, swaps the running enclave on the build host, re-pins, then dispatches the fleet refresh |
| `enclave-fleet-refresh.yml` | Bakes an AMI from the build host, points the launch template at it, rolls the autoscaling group |
| *publish* (a PR) | Makes the new measurement `current` and prunes the outgoing one from `accepted_pcr0` and from the KMS allow-list |
| `enclave-drift.yml` | Daily: compares what is published against what every box actually serves, from the outside, the way a client would; also reads the Azure standby's certificate for api.ppq.ai. Opens (and later closes) a canonical "Enclave drift detected" issue |

A stale entry in `accepted_pcr0` silently re-admits a retired image, so the
prune is part of the release, not housekeeping.

## Verifying the enclave

The privacy guarantee only holds if the client checks attestation *before*
sending a query. `GET /attestation?nonce=<hex>` returns an AWS-signed (Nitro
Security Module) COSE_Sign1 document that echoes the nonce and commits to
**both** key materials:

| Field | Contents | Who uses it |
|---|---|---|
| `user_data` | **SHA-256 of the TLS certificate's SPKI** | clients that can read the peer certificate pin the connection they are on |
| `public_key` | the enclave's **HPKE (EHBP) public key** | browsers seal the request body to it |

The same values are repeated outside the document as `cert_spki_sha256` and
`hpke_public_key` for convenience; only the copies *inside* the signed document
are evidence.

**Reference verifier** (Node, full chain). It talks to the host's `:8443`
forwarder directly (the enclave's own server name, no nginx in the path), which
the security group opens to one operator IP:

```bash
cd client && npm install
node verify.mjs --host <build host IP> --port 8443 \
  --expect-pcr0 <PCR0 from attestation/published-pcr.json> --credit-id <ppq-credit-id>
```

It (1) fetches the TLS certificate, (2) fetches the attestation over that same
pinned connection, (3) verifies the COSE signature, (4) verifies the certificate
chain up to the pinned **AWS Nitro root** (`client/aws-nitro-root-g1.pem`),
(5) checks validity windows, (6) checks the nonce, (7) checks **PCR0 == the
published measurement**, and (8) checks the attestation is **bound to the TLS
certificate**. Any failure aborts before a single byte of the query is sent.

**Browser verifier:** `client/browser-verify.mjs` performs the same checks with
WebCrypto and returns the HPKE key; `client/nitro-secure-fetch.mjs` wraps it
into an encrypting `fetch`. This is what the web app ships.

**From the outside, the way CI does it daily:**

```bash
node scripts/check-live-attestation.mjs --host enclave.ppq.ai
```

**Provenance of the published number itself:** builds emit a Sigstore
attestation over the `PCR.json` they produce. Download it from the build run's
artifacts and run `gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy`
— the measurement traces to a workflow run in this public repository rather
than to PayPerQ's word.

### What `/health` tells you

`GET /health` is unauthenticated and is what the load balancer polls. Fields
worth knowing when reading it:

| Field | Meaning |
|---|---|
| `key_sources` | per provider: `kms` (attestation-gated) or the plaintext fallback |
| `acme_store` | the sealed store's boot round-trip: `ok`, `failed`, or `absent` |
| `acme_certificates` | the served certificate(s) and their `not_after` |
| `acme_renewal` | `mode` (`dns01-ci` or in-enclave `alpn`), whether this box is the renewal `authority`, whether the CI endpoints are enabled |
| `hpke_identity` | `store` (shared fleet identity), `generated` (no store configured), `rejected` (a stored identity failed to load; this box is on a fresh key and the store was left untouched) |
| `hpke_public_key` | must be identical on every box; the drift check enforces it |
| `workers` / `worker` / `pid` | cluster size and which worker answered |
| `proxy_protocol` | `true` when this enclave also listens on the PROXY-protocol port for the api path (a config fact, identical on every worker) |
| `counters` | per-worker request counters since this worker started: `requests`, `by_outcome` (exactly one per request — an error code, `unauthenticated`, `upstream_error_status`, or the terminal stream end; sums to `requests` once every request has finished; an in-flight request has no outcome yet), `error_reports` (one per report attempted, whether or not it was delivered; a request can send several), `by_provider`, `ehbp`, `streaming`, `open_streams`, `settle.queued` / `settle.permanent_failures`. Enum keys and integers only; sum across workers for a box |

## Attested routing receipts — checking where your request went

Attestation proves the enclave runs published code. It does **not** prove your
request went where you asked, because the enclave does not choose the upstream:
horse-power does, at `/enclave/authorize`, and horse-power is an ordinary web
app with no measurement attached. Provider or model substitution decided there
would otherwise be invisible.

Every streamed response therefore carries a **routing receipt**: an SSE
comment, signed with a key the attestation document commits to.

```
: ppq-routing-receipt {"v":1,"requested_model":"anthropic/claude-sonnet-5",
    "upstream":"api.anthropic.com","upstream_model":"claude-sonnet-5",
    "route":"direct","provider":"anthropic","upstream_status":200,
    "skipped":[],"failed":[],"upstream_selects_provider":false}
: ppq-routing-receipt-sig {"alg":"ECDSA-SHA256","over":"receipt_json_utf8","sig":"…"}
```

`alg` follows the key type of the attested SPKI: `ECDSA-SHA256` (DER-encoded
ECDSA over SHA-256) for a P-256 key, which is every key the enclave holds, or
`RSA-PSS-SHA256` (salt length = digest length) for an RSA one. A verifier
chooses its parameters from the SPKI, not from the label, and checks that the
two agree (`client/verify-receipt.mjs` does both).

Every SSE parser and the OpenAI SDKs ignore comment lines, so it is invisible
to clients that do not look for it.

### Check one yourself

```bash
node client/verify-receipt.mjs --key sk-... --pcr0 <the measurement you pinned>
```

It walks the whole chain rather than asserting any of it: fetch `/attestation`,
hash the certificate SPKI, require that hash to appear **inside** the
NSM-signed document, then verify the receipt signature against that key. The
third step is the load-bearing one — without it a host could hand you any key
and sign anything with it. The script also flips the `upstream` field and shows
the signature breaking, so the property is demonstrated rather than claimed.

### What a receipt does not tell you

- **Not that the enclave runs the code we published.** That is the PCR0 pin, a
  separate check against `attestation/published-pcr.json`.
- **On an OpenRouter route, the guarantee stops at OpenRouter's door.**
  OpenRouter picks the underlying provider itself. The receipt states this in
  `upstream_selects_provider`; a reader who ignores that field will conclude
  more than the receipt claims.
- **Nothing about what the provider then did with your data.** Only where the
  request went.

Prevention, as opposed to evidence, is the family binding in
`enclave/src/upstreamBinding.mjs`: a coarse map measured into PCR0 under which
`anthropic/*` may only reach `api.anthropic.com` or `openrouter.ai`. The
enclave refuses a candidate that violates it, so horse-power keeps choosing
among permitted upstreams and loses the ability to choose an impermissible one.

## Observability — what leaves the enclave about a request

A private request leaves horse-power one billing row, and since this slice a
**trace** rides that row (and any error report) so support can look up what
happened to a request by credit id without anyone reading it. Everything in it
is either a number, a boolean, or a string drawn from a fixed vocabulary or
checked against a shape (`trace.mjs`, `sanitizeTrace`):

- **Timings and sizes:** `t_authorize_ms`, `t_upstream_connect_ms`,
  `t_first_token_ms`, `t_total_ms`, `bytes_out` (plaintext bytes written to the
  client, before any EHBP framing, so it means the same for sealed and
  unsealed responses).
- **Envelope facts:** `streaming` (the caller asked for a stream), `ehbp` (the
  body arrived HPKE-sealed), `max_tokens_cap_applied` and the cap.
- **The route,** in the same terms as the routing receipt: which provider
  served (`openrouter` / `fireworks` / `bedrock` / `anthropic` / `vertex`), the
  hostname the enclave's TLS validated, the API dialect, and the candidates it
  skipped or that failed ahead of it — at most 8 of each, reasons drawn from the
  eligibility enum, statuses as integers.
- **How the stream ended:** `clean`, `upstream_error`, `client_abort` or
  `cap_hit`.
- **Two header-derived scalars, both bounded:** the caller's `x-request-id`
  only if it matches `^[A-Za-z0-9._-]{1,64}$` (dropped otherwise, because it is
  caller-controlled text), and the first 200 characters of the `User-Agent`
  only if they are printable ASCII.
- **`client_ip`**, only when a listener attached one to the socket
  (`req.socket.clientIp`, set by the PROXY-protocol listener on the api port;
  absent on the 443 path). Never taken from a header the caller could set.
- **Which enclave:** the image version, the cluster worker, and the parent's
  EC2 instance id (`box_id` in the init blob).

What never leaves: anything from the request or response body — no prompt, no
completion, no tool call, no error text a provider quoted back, no model string
the enclave did not get from horse-power. Failure reports (`errorReport.mjs`)
are a fixed enum of codes plus shape-checked identifiers, the upstream's HTTP
status where there was one, and the same sanitized trace when the failure
happened late enough for one to exist; `client_abort`,
`authorize_unreachable`, `authorize_timeout` and `settle_failed_permanent` are
the codes this slice added. A failure to build or send a trace is logged
inside the enclave and never affects the response or the settlement.

`/health` carries per-worker counters of the same enum values. `by_outcome`
records exactly one outcome per request — an error code (or `unauthenticated`)
for a request that ended early, `upstream_error_status` for a passed-through
upstream error, else the terminal stream end (`clean`, `cap_hit`,
`upstream_error`, `client_abort`) — so it sums to `requests` once every request has finished; an in-flight request is counted in `requests` with no outcome yet. `error_reports`
counts report attempts, one per report (before the send, so an undelivered report still counts): a single request can send several (a
skipped direct candidate, a 4xx passed through and then streamed, a settle
that fails later), which is why they are not outcomes. Settle losses appear
only under `settle.permanent_failures`.

## Layout

```
enclave/
  boot.sh                 in-enclave entrypoint: tunnels, KMS decrypt, init blob, exec
  Dockerfile              pinned base images; no third-party runtime deps
  attest/                 Go helper that asks the NSM for an attestation document
  kmstool/                kmstool_enclave_cli build stage (attestation-gated KMS calls)
  test/                   node:test suites for the modules below
  src/
    server.mjs            TLS server, cluster primary/worker, request path, /health, /attestation
    proxyProtocol.mjs, proxyListener.mjs
                          PROXY protocol v1+v2 parser and the second inbound port (api path) that
                          reads the header, then hands the connection to the same TLS server
    authorizeHeaders.mjs  what /enclave/authorize is told: credential allow-list + MAC'd client ip
    clusterProto.mjs      primary<->worker messages (state, challenges, certs, creds, RPC)
    hpkeIdentity.mjs      load the shared EHBP identity from the store, or generate one
    ehbp-server.mjs       HPKE seal/open (EHBP)
    acme.mjs, acmeRunner.mjs, acmeStore.mjs, acmeTransport.mjs
                          ACME client, in-enclave issuance, CI-driven renewal, sealed store
    trustRoots.mjs        pinned ISRG roots the installed chain must verify to
    keySources.mjs        which provider keys came from KMS vs the fallback
    routing.mjs, eligibility.mjs, upstreams.mjs, upstreamBinding.mjs
                          model resolution, provider eligibility, allowed upstreams per family
    anthropic.mjs, bedrock.mjs, bedrockCreds.mjs, sigv4.mjs, vertexAuth.mjs
                          direct-provider dialects and signing
    cost.mjs, settleQueue.mjs, receipt.mjs, rebrand.mjs, webSearchTransforms.mjs
    errorReport.mjs, trace.mjs, counters.mjs
                          what leaves the enclave about a request: coded failure reports,
                          the content-free per-request trace, the /health counters
client/
  verify.mjs              reference verifier (Node)
  browser-verify.mjs      attestation verifier for browsers (WebCrypto)
  nitro-secure-fetch.mjs  verify + EHBP-seal, as an encrypting fetch
  verify-receipt.mjs      routing-receipt verifier
  ehbp-live-test.mjs      end-to-end EHBP test against the live endpoint
attestation/
  published-pcr.json      the trust anchor clients read; PUBLISHED_PCR.md is the history
scripts/
  build-enclave.sh        docker build -> nitro-cli build-enclave -> PCR.json
  run-host.sh             host plumbing: vsock-proxies, inbound forwarder(s), run-enclave, store listener
  send-init.sh            init blob over vsock (config, KMS ciphertexts, sealed store from S3)
  send-creds.sh           Bedrock STS credential refresh over vsock (systemd timer)
  nginx-sni-split.conf    the SNI-preread stream block on :443 (and the rollback it keeps),
                          plus the documented api arm (:8445, proxy_protocol on)
  nginx-pp-arm.conf       that api arm alone, wrapped in its own stream {} (a box with no stream context: the dev box)
  nginx-pp-arm-server.conf
                          the arm's server block alone, for a box that already has the stream block (production)
  install-pp-arm.sh       installs either form on a box, idempotently; --uninstall reverses it
  pp-forwarder.sh         the host-side socat on /run/ppq/pp.sock -> vsock:8445 (run-host.sh calls it; runnable alone)
  renew-cert-dns01.mjs    the CI side of certificate renewal
  renew-azure-cert-dns01.mjs, check-azure-standby-cert.mjs
                          the Azure standby's own certificate for api.ppq.ai, and its expiry check
  lib/                    dns01.mjs (GoDaddy DNS-01 flow shared by both renewals), azureCert.mjs
  check-live-attestation.mjs, check-drift.py, kms-pcr0-allow.py
  fleet/                  boot-enclave.sh (a box starts its own enclave), create-nlb.sh, create-api-nlb.sh
  systemd/                ppq-enclave.service and the Bedrock creds timer
.github/workflows/        build, cutover, fleet refresh, drift check, certificate renewal (enclave, and the Azure standby)
```

## Testing changes safely

Enclave source changes cannot be tested by unit tests alone: `boot.sh` and the
TLS handshake path only fail when an enclave actually boots or a client
actually connects. There is a **dev enclave** for this — a second Nitro host
with its own hostname and no access to any production secret. See
[DEV-ENCLAVE.md](DEV-ENCLAVE.md). Stop it when you are done; it bills by the
hour.

## Reproducible builds

```bash
# On a Nitro-enabled instance:
./scripts/build-enclave.sh
cat build/PCR.json   # {base_image, PCR0, PCR1, PCR2}
```

`build-enclave.sh` pins every input (base images by digest, apt by snapshot,
Go and npm by lockfile) and records them next to the resulting PCR values.
Rebuild from a tagged commit → identical `PCR0`. [REPRODUCE.md](REPRODUCE.md)
walks through it and lists the one remaining input that is not snapshot-pinned.

## Status

**Working, in production:** TLS terminating inside the enclave on
`enclave.ppq.ai` with a browser-trusted certificate; EHBP for browsers;
attestation-gated provider keys; content-free billing; signed routing
receipts; a load-balanced, autoscaling fleet sharing one measurement, one
identity and one certificate; unattended certificate renewal with the key
in-enclave; daily external drift checking.

### Known gaps — read before quoting the privacy claim

1. **An unsealed body is accepted silently.** `server.mjs` opens the HPKE seal
   only when `Ehbp-Encapsulated-Key` is present; otherwise it parses the raw
   body. Attested TLS still protects that body from the parent — but only for
   a client that verified the certificate against the attestation. A browser
   that omits EHBP has no such check and gets **no error**. This fails open.
2. **KMS gating vs. the plaintext fallback.** The image builds
   `kmstool_enclave_cli`, but `boot.sh` falls back to init-channel plaintext
   keys when the ciphertext or the tool is absent. Confirm which mode a given
   boot used before claiming attestation-gated custody — `/health` answers it
   per provider under `key_sources`.
3. **The rollback path still exists on every box.** nginx keeps a
   host-terminated arm (`127.0.0.1:8444`, with the old certbot certificate)
   that one map line and a reload would put `enclave.ppq.ai` back on. It is
   the emergency exit if in-enclave TLS ever has to be backed out, and while it
   is in use the trust property described above does not hold. The daily drift
   check would report it (served SPKI ≠ attested SPKI).
4. **Metadata is not protected**, and is not claimed to be — see
   [Threat model](#threat-model).

**Also remaining:** commit `go.sum` for a byte-reproducible build; signed
authorize grants.

### Bedrock direct upstream (api_style: 'bedrock')

OpenAI frontier models served straight from AWS Bedrock inside the enclave —
via the **OpenAI Responses API on the bedrock-mantle endpoint**
(`https://bedrock-mantle.<region>.api.aws/openai/v1/responses`), the ONLY
surface that serves these models (live-probed 2026-08-14: Converse,
ConverseStream, InvokeModel and bedrock-runtime all reject them). hp's
`/enclave/authorize` offers a `bedrock` candidate; the enclave runs the SHARED
eligibility gate + projection first, then `bedrock.mjs` maps the chat body to
the Responses dialect (always `store: false` — the API persists by default and
this proxy exists so content never rests outside the enclave), `sigv4.mjs`
signs the exact bytes under service name `bedrock-mantle` with short-lived STS
creds, and the Responses SSE stream is translated back into chat-completions
SSE for the existing cost/rebrand pipeline (usage passes through verbatim —
subset convention, cache-write premium priced hp-side). Credentials are
re-delivered by the host every ~30 min over the persistent vsock:7001 creds
channel (`scripts/send-creds.sh`) — KMS-enveloped under the attestation-gated
CMK (preferred) or plaintext (fallback; an expiration is REQUIRED either way).
Anything missing — tunnel, creds, an unmappable field — skips the candidate
and the request rides OpenRouter, exactly like the Fireworks path.
