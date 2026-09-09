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
| `enclave-drift.yml` | Daily: compares what is published against what every box actually serves, from the outside, the way a client would. Opens (and later closes) a canonical "Enclave drift detected" issue |

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
: ppq-routing-receipt-sig {"alg":"RSA-PSS-SHA256","over":"receipt_json_utf8","sig":"…"}
```

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
  run-host.sh             host plumbing: vsock-proxies, inbound forwarder, run-enclave, store listener
  send-init.sh            init blob over vsock (config, KMS ciphertexts, sealed store from S3)
  send-creds.sh           Bedrock STS credential refresh over vsock (systemd timer)
  nginx-sni-split.conf    the SNI-preread stream block on :443 (and the rollback it keeps)
  renew-cert-dns01.mjs    the CI side of certificate renewal
  check-live-attestation.mjs, check-drift.py, kms-pcr0-allow.py
  fleet/                  boot-enclave.sh (a box starts its own enclave), create-nlb.sh
  systemd/                ppq-enclave.service and the Bedrock creds timer
.github/workflows/        build, cutover, fleet refresh, drift check, certificate renewal
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
