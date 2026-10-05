# ppq-enclave-proxy

A confidential-computing proxy for PayPerQ chat. It runs inside an **AWS Nitro
Enclave** so that **PayPerQ cannot observe the content** of user queries or
model responses. Every chat completion PayPerQ serves, whether from the web
app (`enclave.ppq.ai`) or the public API (`api.ppq.ai`), terminates its TLS
*inside* the enclave; the enclave calls the model provider, and PayPerQ's
backend (horse-power) is never on the byte path. It receives only **billing
metadata**: token counts, cost, credit id, and a content-free trace.

This repository is **public and its builds are reproducible on purpose**: the
privacy claim only holds if anyone can rebuild this exact source, reproduce the
enclave measurement (`PCR0`), and verify that the running enclaves match. See
[Reproducible builds](#reproducible-builds) and [REPRODUCE.md](REPRODUCE.md).

Current published measurement: [`attestation/published-pcr.json`](attestation/published-pcr.json)
(history in [`attestation/PUBLISHED_PCR.md`](attestation/PUBLISHED_PCR.md)).
How the boxes are run is in [OPERATIONS.md](OPERATIONS.md); this file is the
claim and how to check it.

## If you only read one section: verify it

Four checks, from cheapest to most complete. Each one is something PayPerQ
cannot fake for you.

1. **The certificate you were served is the one the enclave attests to.**
   Nothing on the parent can read the stream if this holds.
   ```bash
   # the SPKI hash of the certificate you were actually served
   echo | openssl s_client -connect enclave.ppq.ai:443 -servername enclave.ppq.ai 2>/dev/null \
     | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256
   # the value the NSM-signed attestation document commits to; these MUST match
   curl -s "https://enclave.ppq.ai/attestation?nonce=$(openssl rand -hex 16)" | jq -r .cert_spki_sha256
   ```
   Repeat with `api.ppq.ai` in both places for the API path.
2. **The enclave runs the published code.** Verify the attestation document's
   signature chain to the AWS Nitro root and its `PCR0` against
   `attestation/published-pcr.json`:
   ```bash
   node scripts/check-live-attestation.mjs --host enclave.ppq.ai
   ```
3. **Your request went where you paid for it to go.** Send one and verify its
   signed routing receipt against the same attestation:
   ```bash
   node client/verify-receipt.mjs --key sk-... --pcr0 <the measurement you pinned>
   ```
4. **The published number came from this source.** Rebuild it
   ([REPRODUCE.md](REPRODUCE.md)), or check the Sigstore attestation on the
   build that produced it:
   `gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy`.

The rest of this document explains what each check proves and, just as
important, what it does not.

## Threat model

**What this protects.** PayPerQ, meaning the parent EC2 instances, their
operators, the backend, databases and logs, cannot read the **content** of a
request or a response. The client's TLS session ends inside the enclave, with a
browser-trusted Let's Encrypt certificate whose private key was generated in an
enclave and has never existed outside one. The parent forwards encrypted bytes
and holds no key that could open them.

**What PayPerQ still sees.** Metadata, and no claim of unlinkability is made:

- The enclave settles every request to horse-power with the credit id, model,
  token counts and cost, plus a content-free routing trace: timings, the route
  taken, and the request's *shape* (field names, message and tool counts,
  routing preferences; see
  [Observability](#observability-what-leaves-the-enclave-about-a-request)).
  PayPerQ can therefore tie an account to a timestamp, a model, a response
  size and the client's request settings. It cannot read the text.
- The parent instance sees the TLS server name (SNI is cleartext in every TLS
  handshake), connection timing and byte counts. On the `api.ppq.ai` path it
  also sees the client's IP address, which it passes to the enclave and on to
  horse-power (see [The api path](#the-api-path-proxy-protocol)). On the
  `enclave.ppq.ai` path the parent logs the load balancer's private address,
  but the load balancer itself, being AWS infrastructure PayPerQ operates,
  sees the client IP. Do not read "the parent is blind" as "PayPerQ cannot
  learn your IP".

**What this does NOT protect.** The upstream model provider (OpenRouter,
Anthropic, Fireworks, Venice, Google Vertex, AWS Bedrock) receives plaintext;
it must, to run inference. The guarantee is *"PayPerQ is blind,"* not
end-to-end secrecy from every party. The exception is the `private/*` models,
which run inside Tinfoil's confidential VMs: for those the provider is blind
too. See [Tinfoil private models](#tinfoil-private-models-private-the-relay-and-the-seal-on-your-behalf).

**What this covers.** Chat completions and the structured-decision endpoint.
Every other PayPerQ route that reaches the enclave on `api.ppq.ai` (image,
video and audio generation, transcription, balance, data endpoints) is
[passed through](#routes-the-enclave-does-not-serve-the-transparent-proxy) to
horse-power verbatim; those requests transit the enclave but carry no privacy
claim.

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
  │  TLS ──▶ NLB (client IP kept) ──▶ nginx :8445 ──▶ socat :8445 ──vsock──▶│   present                │
  │          api.ppq.ai                PROXY v1 line   raw bytes             │ eligibility + routing    │
  │                                                                          │ provider keys via        │
  │                                                                          │   attestation-gated KMS  │
  │                                                                          │ calls the upstream ──────┼──▶ provider
  │                                                                          │ extracts usage/cost      │
  │                                                                          │ signs a routing receipt  │
  │                                                                          │ POST /enclave/settle ────┼──▶ horse-power
  │                                                                          └──────────────────────────┘    (metadata only)
```

**Nothing on the parent can read the stream.** Both load balancers are Network
Load Balancers with plain TCP listeners; nginx runs `ssl_preread` and forwards
by server name without terminating; socat bridges TCP to the enclave's vsock.
None of them holds a private key for any of the public names. The certificate
the client is served is the one the NSM-signed attestation commits to, and
`scripts/check-live-attestation.mjs`, run every six hours from CI against every
box, is designed to catch precisely a mismatch.

### The hostnames

| Hostname | What it is | Who uses it |
|---|---|---|
| `api.ppq.ai` | The api NLB in front of every enclave box, port 8445 with PROXY protocol. About 95% of new connections | API clients, SDKs, the npm proxy |
| `enclave.ppq.ai` | The NLB in front of every enclave box, port 8443 | The web app |
| `enclave-direct.ppq.ai` | The build host's own Elastic IP, no load balancer | Certificate renewal from CI, the reference verifier, operators |
| `enclave-dev.ppq.ai` | A separate dev enclave with no production secrets ([DEV-ENCLAVE.md](DEV-ENCLAVE.md)) | Testing measured-code changes |

All three production names are on one certificate and all three terminate
inside the enclave. The difference is only *which box* you reach: the direct
name always lands on the build host, which is the single renewal authority;
the public names land on whichever box the load balancer picks. Every box
presents the same `PCR0`, the same HPKE key and the same certificate, so a
client never needs to know or care which one answered.

### The api path (PROXY protocol)

`api.ppq.ai` needs the client's address, because horse-power rate-limits,
geo-blocks and logs by it, and nothing on the path can put it in an HTTP
header, because nothing on the path sees HTTP. The one mechanism that works
*below* TLS is [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt):
nginx, the last hop that knows the address, prepends a small text line to the
connection, and the enclave reads it before it starts the handshake
(`proxyListener.mjs`, which parses v1 and v2). The address is recorded as
`req.socket.clientIp`, taken from that header alone and never from
`x-forwarded-for` or any header a client can send. From there the request is
handled identically to the `enclave.ppq.ai` path; the differences are that the
trace's `client_ip` is present and that the authorize call and every proxied
route carry an `x-ppq-client-ip` pair, MAC'd with the settle secret over the
address and the current Unix minute, so nothing between the enclave and
horse-power can substitute another address.

The client address is asserted by the host, exactly like the load balancer's
own view of the peer. Its integrity rests on the host; it is not part of the
privacy claim, and the [threat model](#threat-model) already states that the
parent sees IPs and metadata. How the arm is installed, why only nginx can
write the header, and why the two paths are two ports rather than a flag are
in [OPERATIONS.md](OPERATIONS.md#the-api-arm-8445-proxy-protocol).

### EHBP: why a second layer still exists

Requests may additionally carry an HPKE-sealed body (EHBP, header
`Ehbp-Encapsulated-Key`), sealed to the enclave's HPKE public key. With TLS
already ending in the enclave this looks redundant; it is not, for one class of
client: **browser JavaScript cannot read its own TLS peer certificate**, so a
page can verify an attestation perfectly and still have nothing to compare its
connection against. A malicious host could terminate the browser's TLS and
proxy the attestation through. EHBP closes that: the browser verifies the
attestation, takes the HPKE key *from inside the signed document*, and seals to
it. The web app does this.

SDK and CLI clients that *can* inspect the certificate get the same property
from attested TLS alone. Both paths remain, and `/attestation` commits to both
keys (see the table under [Verifying the enclave](#verifying-the-enclave)).

### Outbound, keys, billing

- **Outbound:** the enclave reaches every upstream, KMS, Let's Encrypt and
  horse-power through host-side `vsock-proxy` hops. TLS to each is validated
  inside the enclave against the real hostname; the proxy forwards bytes and
  can only choose *whether* a connection happens, never read it. The allow-list
  is written by `scripts/run-host.sh`: `openrouter.ai`, `api.fireworks.ai`,
  `api.anthropic.com`, `api.venice.ai`, `aiplatform.googleapis.com`,
  `oauth2.googleapis.com`, `bedrock-mantle.{us-east-1,us-east-2,us-west-2}.api.aws`,
  `inference.tinfoil.sh`, `atc.tinfoil.sh`, the settle host, Let's Encrypt
  (production and staging) and KMS. Nothing else is reachable from inside.
- **Key custody:** provider API keys are KMS-encrypted and `kms:Decrypt` is
  gated on `kms:RecipientAttestation:PCR0`, so KMS releases them **only** to an
  enclave whose measurement is on the published allow-list. Operators cannot
  extract them. `boot.sh` falls back to a plaintext key from the init channel
  when the ciphertext or the tool is absent, or when the decrypt fails;
  `/health` reports which happened per provider under `key_sources` (see
  [Known gaps](#known-gaps--read-before-quoting-the-privacy-claim)).
- **Billing:** the enclave never writes to a database. It reports token counts
  and cost to horse-power `POST /enclave/settle`, which applies the margin and
  debits credits. The call is idempotent by a `settle_id` the enclave mints per
  request; the client's `x-request-id` is carried alongside for correlation
  but is deliberately **not** the idempotency key, because a client that
  reused one would have every request after the first served and never
  billed. Nothing in the call is content; the full field list is under
  [Observability](#observability-what-leaves-the-enclave-about-a-request).

## Routes the enclave does not serve: the transparent proxy

On `api.ppq.ai`, which carries more than chat, the request router runs a thin
check first: is this `method + path` one the enclave serves itself?

- `POST /chat/completions`, `POST /v1/chat/completions`
- `POST /v1/decisions`, `POST /decisions`, `POST /v1/systemone`
  (structured-decision models, `decisions.mjs`)
- `POST /private/v1/chat/completions`, `POST /private/chat/completions`,
  `GET|POST /private/attestation`, `GET /private/.well-known/hpke-keys`
  (the Tinfoil private models, `tinfoil.mjs`)
- `GET /health`, `GET /attestation`
- `POST /acme/csr`, `POST /acme/install` (404 unless this box is the renewal
  authority and the CI token matches)
- OPTIONS on any of those

If not, `passthrough.mjs` forwards it to horse-power over the settle tunnel,
unbuffered, and relays the answer, including `Upgrade` for the transcription
WebSocket. The check runs per request, not per connection, so a keep-alive
connection can carry a proxied `/v1/models` and then an in-enclave chat call
without the chat ever leaving the enclave.

"Verbatim" has a short list of exceptions, all on the request side: hop-by-hop
headers are dropped; `Host` is replaced; every inbound header that could claim
a client address (`x-forwarded-*`, `x-real-ip`, `x-client-ip`,
`cf-connecting-ip`, `true-client-ip`, `forwarded`, and any `x-ppq-client-ip*`)
is stripped and the enclave adds its own MAC'd pair; and `/hp/health` is
rewritten to horse-power's `/health` for a monitor that wants the backend's
answer through the same hostname. An `Upgrade` request on the api path goes to
horse-power whatever its path, enclave routes included. The proxy allows 512
requests in flight (503 beyond that), waits 240 s for a status line, and keeps
idle upstream sockets for 30 s.

This is a compatibility shim, not a privacy claim: those routes are served by
horse-power exactly as before and merely transit the enclave. It is enabled by
`passthrough_host` in the init blob, and even then only for connections that
arrived through the PROXY-protocol port with a client address in the header
(an addressless `UNKNOWN` or `LOCAL` header completes the handshake but is not
proxied). On the plain port, `enclave.ppq.ai`'s, unknown routes stay 404
whatever the blob says (an `Upgrade` there is dropped, and OPTIONS on any path
answers 204 with CORS headers): configuring a passthrough host never widens
what that hostname serves, and no proxied request leaves without a client
address horse-power can rate-limit and geo-block by.

## The fleet: how this scales without weakening the claim

Both public names are served by the build host plus an autoscaling group of
identical boxes (`scripts/fleet/`). Three things had to become shared for a
fleet to be possible at all, and each is shared *inside* the trust boundary:

1. **One measurement.** `PCR0` is a property of the image, not the machine. A
   fleet of boxes booted from one image publishes one hash, and the drift
   check visits every healthy box every six hours to confirm they all present
   it.
2. **One EHBP identity.** The HPKE key pair lives in the sealed store, a blob
   enveloped under a data key from the attestation-gated CMK, so the parent
   that stores and copies it holds ciphertext it cannot open. Every box
   unseals the same identity at boot and `/health` reports
   `hpke_identity: store` when it did. A box that could not load a stored
   identity serves a fresh key and reports `rejected` rather than silently
   overwriting the shared one.
3. **One certificate.** The private key was generated in an enclave and is
   distributed only inside that same sealed blob. Renewal runs daily from CI
   with the key never leaving the enclave: the authority enclave produces a
   fresh key and CSR, CI proves control of the three names to Let's Encrypt
   over DNS-01, and hands the issued chain back to the enclave, which verifies
   it against pinned ISRG roots before installing it and re-sealing the store.
   The fleet is then rolled so every box boots from the new blob. Exactly one
   box, the build host, is the renewal authority; every other box is a
   consumer.

Inside each enclave a Node `cluster` can run several workers behind one port;
the primary alone owns the store, the identity, ACME and credential delivery,
so adding workers adds capacity without adding writers. The default is a
single worker (`enclave_workers` in the init blob); `/health` reports
`workers` and which `worker` answered.

Autoscaling policy, scaling alerts, the load balancers, and the Azure standby
that keeps `api.ppq.ai` answerable if the enclave path is ever backed out are
described in [OPERATIONS.md](OPERATIONS.md).

## Rotation: how a new image reaches production

Every change to the enclave is a new measurement, so shipping is a trust event
and is done by CI, in the open, in this order:

| Workflow | What it does |
|---|---|
| `enclave-build.yml` | Reproducible build; emits `PCR.json` and a Sigstore attestation over it. Runs on every push to `main` that touches a measured path |
| *pre-accept* (a PR to `published-pcr.json`) | Adds the incoming `PCR0` to `accepted_pcr0` **alongside** the current one, so a client that honours the list keeps accepting the enclave through the swap. The cutover refuses to run until this has merged |
| `enclave-cutover.yml` | Gated on the `production-enclave` environment. Adds the new `PCR0` to the KMS allow-list, swaps the running enclave on the build host, delivers Bedrock credentials, verifies the measurement, prunes KMS to {running, previous}, smoke-tests, re-pins the web app's fallback, then dispatches the fleet refresh |
| `enclave-fleet-refresh.yml` | Refuses if the EIF on disk differs from the running enclave; otherwise bakes an AMI from the build host, points the launch template at it, rolls the autoscaling group |
| *publish* (a PR) | Makes the new measurement `current` and prunes the outgoing one from `accepted_pcr0` and from the KMS allow-list |
| `enclave-drift.yml` | Every six hours: compares what is published against what every healthy box behind `enclave.ppq.ai` actually serves, from the outside, the way a client would; also reads the Azure standby's certificate for `api.ppq.ai`. Opens (and later closes) a canonical "Enclave drift detected" issue |

A stale entry in `accepted_pcr0` silently re-admits a retired image, so the
prune is part of the release, not housekeeping.

## Verifying the enclave

The privacy guarantee only holds if the client checks attestation *before*
sending a query. `GET /attestation?nonce=<hex>` returns an AWS-signed (Nitro
Security Module) COSE_Sign1 document that echoes the nonce and commits to
**both** key materials:

| Field | Contents | Who uses it |
|---|---|---|
| `user_data` | **SHA-256 of the TLS certificate's SPKI**, for the connection the request arrived on | clients that can read the peer certificate pin the connection they are on |
| `public_key` | the enclave's **HPKE (EHBP) public key** | browsers seal the request body to it |

The same values are repeated outside the document as `cert_spki_sha256`
(with `cert_spki_der`) and `hpke_public_key` for convenience; only the copies
*inside* the signed document are evidence. A nonce that is not even-length hex
of at most 128 characters is ignored, not rejected, so check that the document
echoes yours.

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
into an encrypting `fetch`. The web app ships its own copy of these two files
(`utils/crypto/nitroVerify.mjs`, `nitroSecureFetch.mjs` in the PPQdotAI
repository), which is ahead of the copies here: it accepts up to two `PCR0`
values, which is how the `accepted_pcr0` rollover described under
[Rotation](#rotation-how-a-new-image-reaches-production) actually reaches
users. The reference clients in `client/` still pin a single `PCR0`; treat the
web app's copy as canonical until they are brought level.

**From the outside, the way CI does it every six hours:**

```bash
node scripts/check-live-attestation.mjs --host enclave.ppq.ai
```

**Provenance of the published number itself:** builds emit a Sigstore
attestation over the `PCR.json` they produce. Download it from the build run's
artifacts and run `gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy`;
the measurement traces to a workflow run in this public repository rather than
to PayPerQ's word.

### What `/health` tells you

`GET /health` is unauthenticated and is what the load balancers poll. Fields
worth knowing when reading it:

| Field | Meaning |
|---|---|
| `key_sources` | per provider (`openrouter`, `fireworks`, `anthropic`, `vertex`, `tinfoil`, `venice`): `kms` (attestation-gated), `init-plaintext`, `init-plaintext-after-kms-failure`, `kms-failed`, or `absent` |
| `acme_store` | the sealed store's boot round-trip: `ok`, `failed`, or `absent` |
| `acme_certificates` | the served certificate(s) and their `not_after` |
| `acme_renewal` | `mode` (`dns01-ci` or in-enclave `alpn`), whether this box is the renewal `authority`, and `ci_endpoint` (whether the CI endpoints are enabled) |
| `hpke_identity` | `store` (shared fleet identity), `generated` (no store configured), `rejected` (a stored identity failed to load; this box is on a fresh key and the store was left untouched) |
| `hpke_public_key` | must be identical on every box; the drift check enforces it |
| `workers` / `worker` / `pid` | cluster size and which worker answered |
| `proxy_protocol` | `true` when this enclave also listens on the PROXY-protocol port for the api path (a config fact, identical on every worker) |
| `passthrough` | whether the transparent proxy is armed |
| `tinfoil` | `configured`, `verified`, `verified_at`, `measurement`, `last_error` for the Tinfoil attestation; never the key |
| `counters` | per-worker request counters since this worker started: `requests`, `by_outcome` (exactly one per finished request; see [Observability](#observability-what-leaves-the-enclave-about-a-request)), `error_reports`, `by_provider`, `ehbp`, `streaming`, `open_streams`, `settle.queued` / `settle.permanent_failures`. Enum keys and integers only; sum across workers for a box |

## Attested routing receipts: checking where your request went

Attestation proves the enclave runs published code. It does **not** prove your
request went where you asked, because the enclave does not choose the upstream:
horse-power does, at `/enclave/authorize`, and horse-power is an ordinary web
app with no measurement attached. Provider or model substitution decided there
would otherwise be invisible.

Every chat response therefore carries a **routing receipt**, signed with a key
the attestation document commits to. A streamed response carries it as an SSE
comment ahead of its first data frame (a `: PPQ.AI PROCESSING` keep-alive
comment may precede it):

```
: ppq-routing-receipt {"v":2,"request_id":"3f9c…","request_id_source":"client",
    "issued_at":"2026-09-29T16:18:52.505Z",
    "requested_model":"anthropic/claude-sonnet-5",
    "upstream":"api.anthropic.com","upstream_model":"claude-sonnet-5",
    "served_model":"claude-sonnet-5-20260101",
    "route":"direct","provider":"anthropic","upstream_status":200,
    "skipped":[],"failed":[],"upstream_selects_provider":false}
: ppq-routing-receipt-sig {"alg":"ECDSA-SHA256","over":"receipt_json_utf8","sig":"…"}
```

A response that is not a stream carries the same two values as response
headers, `Ppq-Routing-Receipt` (the base64 of the JSON the signature is over)
and `Ppq-Routing-Receipt-Sig`, and both are listed in
`Access-Control-Expose-Headers` so a browser can read them. Its `served_model`
is always `null`: headers leave before the answer arrives.

**To tie a receipt to your request, send an `x-request-id` nobody else knows**
and require it back as `request_id` with `request_id_source: "client"`. The
receipt accepts any printable-ASCII id of up to 128 characters. If you send
none, the enclave mints one (`"enclave"`), which tells receipts apart but
proves nothing to a caller who never saw it elsewhere. If you send one that
fails the shape, the receipt carries `request_id: null` and no source; it does
not fall back to a minted id. Version 1 receipts named no request at all, so
two requests for the same model produced identical bytes and a signature taken
from one verified for the other; `verify-receipt.mjs` rejects them.

`upstream_model` is what the enclave sent; `served_model` is what the
upstream's answer said served it, which is the upstream's claim. It is
validated against `^[a-zA-Z0-9._:/@~-]{1,96}$` and is `null` otherwise.
`upstream_selects_provider` is `true` only on the OpenRouter route.

`alg` follows the key type of the attested SPKI: `ECDSA-SHA256` (DER-encoded
ECDSA over SHA-256) for a P-256 key, which is every key the enclave holds, or
`RSA-PSS-SHA256` (salt length = digest length) for an RSA one. A verifier
chooses its parameters from the SPKI, not from the label, and checks that the
two agree. If the enclave does not hold the key for the certificate a
connection was served on, the streamed receipt is sent **unsigned** and the
JSON headers are omitted; a verifier must treat "no signature" as a failure,
not as absence of evidence.

Every SSE parser and the OpenAI SDKs ignore comment lines, so it is invisible
to clients that do not look for it.

### Check one yourself

```bash
node client/verify-receipt.mjs --key sk-... --pcr0 <the measurement you pinned>
```

It walks the whole chain rather than asserting any of it: fetch `/attestation`,
hash the certificate SPKI it was served, require that hash to appear **inside**
the NSM-signed document, then verify the receipt signature against that key.
The third step is the load-bearing one; without it a host could hand you any
key and sign anything with it. It also requires `request_id` to equal the id it
sent, `issued_at` to be within ten minutes of its own clock, and `v` to be 2 or
later, and it flips the `upstream` field to show the signature breaking, so the
property is demonstrated rather than claimed. Other flags: `--host`, `--model`,
`--credit-id`, `--connect <ip>`, `--no-stream`, `--request-id`,
`--published <file>` (defaults to `attestation/published-pcr.json`), and
`--sse <file>` to verify a capture offline.

### What a receipt does not tell you

- **Not that the enclave runs the code we published.** That is the PCR0 pin, a
  separate check against `attestation/published-pcr.json`.
- **On an OpenRouter route, the guarantee stops at OpenRouter's door.**
  OpenRouter picks the underlying provider itself. The receipt states this in
  `upstream_selects_provider`; a reader who ignores that field will conclude
  more than the receipt claims.
- **Nothing about what the provider then did with your data.** Only where the
  request went.
- **Nothing about the content of the answer.** The receipt names the request,
  not the bytes that answered it.
- **Responses outside the chat path carry no receipt:** `/v1/decisions`, the
  pass-through to horse-power, and the client-sealed Tinfoil relay
  (`/private/v1/chat/completions`), where the enclave cannot see what it is
  relaying.

Prevention, as opposed to evidence, is the family binding in
`enclave/src/upstreamBinding.mjs`: a coarse map measured into PCR0 under which
`anthropic/*` may only reach `api.anthropic.com`, `openai/*` only the three
Bedrock endpoints, `google/*` only `aiplatform.googleapis.com`, `venice/*`
only `api.venice.ai` and `private/*` only `inference.tinfoil.sh`, with
`openrouter.ai` permitted for every family as the terminal fallback. The
enclave skips a candidate that violates it (recorded in the receipt's
`skipped` list as `upstream_not_bound_to_family`), so horse-power keeps
choosing among permitted upstreams and loses the ability to choose an
impermissible one. Families not in the map are unconstrained among the hosts
the enclave can reach at all.

One family never takes that terminal fallback. No `venice/*` id exists on
OpenRouter, so when the Venice candidate is skipped or fails the enclave
answers itself (`enclave/src/directOnly.mjs`) instead of forwarding an id
OpenRouter would call invalid: a 400 that names what the request asked for
that the model cannot do, a 429 or 503 when the upstream is rate limited or
unreachable, a 404 when horse-power offered no candidate for it. Nothing is
sent to OpenRouter and nothing is settled. A request refused before any
attempt is sent nowhere; one whose direct attempt failed may have reached
Venice.

## Observability: what leaves the enclave about a request

A private request leaves horse-power one billing row, and a **trace** rides
that row (and any error report) so support can look up what happened to a
request by credit id without anyone reading it. Everything in it is either a
number, a boolean, or a string drawn from a fixed vocabulary or checked against
a shape (`trace.mjs`, `sanitizeTrace`):

- **Timings and sizes:** `t_authorize_ms`, `t_upstream_connect_ms`,
  `t_first_token_ms`, `t_total_ms`, `bytes_out` (plaintext bytes written to the
  client, before any EHBP framing, so it means the same for sealed and
  unsealed responses). Every `t_*_ms` is integer milliseconds since the request
  arrived, measured on a monotonic clock (`performance.now()`), so a wall-clock
  step cannot distort an interval. `t_first_token_ms` is the first byte written
  to the client, not the first generated token.
- **Generation marks:** `t_upstream_sent_ms` (immediately before the first
  upstream request actually issued — candidates skipped before sending do not
  set it, and a later candidate or retry does not move it),
  `t_first_content_ms` (the first upstream frame carrying generated text or
  reasoning, detected on the upstream's own frames before any rewrite;
  keep-alive comments, role-only and empty deltas do not count) and
  `first_token_kind` (`content` — answer text — or `reasoning`; tool calls
  do not count, matching how the backend measures the same interval). Their difference is the same time-to-first-token interval a
  proxy measuring the same request takes. Always present; `null` when the mark
  was not reached (nothing went upstream, no generated text, a non-streamed
  body).
- **Envelope facts:** `streaming` (the caller asked for a stream), `ehbp` (the
  body arrived HPKE-sealed), `max_tokens_cap_applied` and the cap.
- **The route** (`route`): `chosen` (one of `openrouter`, `fireworks`,
  `bedrock`, `anthropic`, `vertex`; a Tinfoil or Venice route is currently
  dropped from this field, see [Known gaps](#known-gaps--read-before-quoting-the-privacy-claim)),
  `upstream_host` (the hostname the enclave's TLS validated), `api_style`, and
  the candidates it `skipped` or that `failed` ahead of it, at most 8 of each,
  reasons drawn from the eligibility enum, statuses as integers, and each
  failure classed `connect_error` / `http_5xx` / `http_4xx` / `http_other`.
  A terminal OpenRouter answer of 429 or 503 is retried once (after the
  upstream's `Retry-After` when it is 2 s or less, else 500 ms; passed through
  at once when it asks for longer), so `failed` can name `openrouter` beside
  a `chosen` of `openrouter`: the first attempt, then the served one.
- **How the stream ended:** `clean`, `upstream_error`, `client_abort` or
  `cap_hit`.
- **Two header-derived scalars, both bounded:** `client_request_id`, the
  caller's `x-request-id` only if it matches `^[A-Za-z0-9._-]{1,64}$` (dropped
  otherwise, because it is caller-controlled text; note this is stricter than
  the receipt's rule, so an id can be signed in the receipt yet absent from the
  trace), and `user_agent`, the first 200 characters of the `User-Agent` only
  if they are printable ASCII.
- **`client_ip`**, only when a listener attached one to the socket
  (`req.socket.clientIp`, set by the PROXY-protocol listener on the api path;
  absent on the 443 path). Never taken from a header the caller could set.
- **Which enclave** (`enclave`): the image `version`, the cluster `worker`, and
  the parent's EC2 instance id (`box`).
- **The request's routing shape** (`request_shape`, `describeRequestShape`):
  what decides where a request is routed, never what it says. The top-level
  field *names* of the body (at most 40, each matching
  `^[A-Za-z_][A-Za-z0-9_.-]{0,47}$`; others are only counted, in
  `fields_dropped`), the model id the caller sent (horse-power already
  receives it at authorization), the number of messages and tools, whether any
  message carries an image, and the values of routing directives only: the
  `provider` preference object as the client sent it (`provider_in`: provider
  slugs, `order`/`only`/`ignore`/`quantizations` up to 16 each, `sort`,
  `allow_fallbacks`, `require_parameters`, `zdr`, `data_collection`, or
  `{invalid: true}`), the `stream` and reasoning knobs (`include_reasoning`,
  `reasoning_enabled`, `reasoning_exclude`, effort), `response_format.type`,
  the `tool_choice` mode (including `function`), and the cache-retention,
  service-tier and verbosity labels, each checked against a short slug shape.
  It also records the `provider` object the enclave placed on the OpenRouter
  request (`provider_out`), so a routing complaint can be answered from the
  row.

Field names and provider labels are client-chosen strings: anything that
passes the slug shape leaves as written, so a client that names a field after a
secret has exported it. Nothing is ever read from a field's *value* except the
routing directives listed above.

What never leaves: the content of the request or response body. No prompt, no
system prompt, no completion, no tool definition or tool-call argument, no
image or file data, no `response_format` schema, no error text a provider
quoted back, and no free-text value of any field.

**The settle row** (`POST /enclave/settle`) carries: `request_id`, `settle_id`,
`credit_id`, `api_key_id`, `model`, `input_tokens`, `output_tokens`,
`usage_source`, `input_tokens_o200k`, `total_cost_usd`, `cost_source`,
`generation_id`, `query_source`, `cache_read_tokens`, `cache_write_tokens`,
`reasoning_tokens`, `is_online`, `web_search_calls` (a count, Venice-direct
only), `is_free_model`, `auto_model`, `is_autoclaw`,
`autoclaw_tier`, `provider`, `upstream_model`, `served_model`, `route`,
`route_bail_reason`, `route_bail_field`, `direct_provider`, and the `trace`.
The decisions endpoint adds `endpoint`; the Tinfoil relay adds `tool_id`.

**Failure reports** (`errorReport.mjs`) are a fixed enum of codes plus
shape-checked identifiers, the upstream's HTTP status where there was one, and
the same sanitized trace when the failure happened late enough for one to
exist. The codes: `request_unreadable`, `model_rejected`,
`model_rejected_not_string`, `model_rejected_smart_routing`,
`model_rejected_private_path`, `transform_failed`, `upstream_unreachable`,
`stream_failed`, `authorize_rejected`, `free_model_unauthorized`,
`upstream_error_status`, `internal_error`, `passthrough_unreachable`,
`client_abort`, `authorize_unreachable`, `authorize_timeout`,
`settle_failed_permanent`, `decisions_usage_missing`, `tinfoil_usage_missing`,
`tinfoil_attestation_failed`. A report's own `request_id` field carries only
an enclave-minted id; a client-supplied id survives in the trace if it fits
the trace's shape. A failure to build or send a trace is logged inside the
enclave and never affects the response or the settlement.

`/health` carries per-worker counters of the same enum values. `by_outcome`
records exactly one outcome per request: an error code (or `unauthenticated`)
for a request that ended early, `upstream_error_status` for a passed-through
upstream error, else the terminal stream end (`clean`, `cap_hit`,
`upstream_error`, `client_abort`). It sums to `requests` once every request
has finished; an in-flight request is counted in `requests` with no outcome
yet. `error_reports` counts report attempts, one per report and counted
before the send, so an undelivered report still counts; a single request can
send several (a skipped direct candidate, a 4xx passed through and then
streamed, a settle that fails later), which is why they are not outcomes.
Settle losses appear only under `settle.permanent_failures`.

## Layout

```
enclave/
  boot.sh                 in-enclave entrypoint: tunnels, KMS decrypt, init blob, exec
  Dockerfile              base images pinned by digest; the kmstool_enclave_cli build stage is inline
  package.json            five runtime dependencies, pinned by lockfile: hpke, @panva/hpke-noble,
                          ehbp, @tinfoilsh/verifier, gpt-tokenizer
  attest/                 Go helper that asks the NSM for an attestation document (go.mod + go.sum committed)
  kmstool/                the Cargo lockfile the kmstool stage builds against
  test/                   node:test suites for the modules below
  src/
    server.mjs            TLS server, cluster primary/worker, request path, /health, /attestation
    proxyProtocol.mjs, proxyListener.mjs
                          PROXY protocol v1+v2 parser and the second inbound port (api path) that
                          reads the header, then hands the connection to the same TLS server
    passthrough.mjs       the transparent proxy for routes the enclave does not serve
    authorizeHeaders.mjs  what /enclave/authorize is told: credential allow-list + MAC'd client ip
    clusterProto.mjs      primary<->worker messages (state, challenges, certs, creds, RPC)
    servedIdentity.mjs    which certificate a connection was served, and the key that signs its receipts
    hpkeIdentity.mjs      load the shared EHBP identity from the store, or generate one
    ehbp-server.mjs       HPKE seal/open (EHBP)
    acme.mjs, acmeRunner.mjs, acmeStore.mjs, acmeTransport.mjs
                          ACME client, in-enclave issuance, CI-driven renewal, sealed store
    trustRoots.mjs        pinned ISRG roots the installed chain must verify to
    keySources.mjs        which provider keys came from KMS vs the fallback
    routing.mjs, smartRouting.mjs, eligibility.mjs, upstreams.mjs, upstreamBinding.mjs
                          model resolution, the auto-router, provider eligibility, allowed upstreams per family
    decisions.mjs         the structured-decision endpoint
    anthropic.mjs, bedrock.mjs, bedrockCreds.mjs, sigv4.mjs, vertexAuth.mjs
                          direct-provider dialects and signing
    tinfoil.mjs           the private/* models: the client-sealed relay, Tinfoil attestation
                          verification, and the EHBP client half that seals on a caller's behalf
    inputEstimate.mjs, outputCount.mjs
                          token estimation for the pre-flight credit check, and output counting
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
  run-host.sh             host plumbing: vsock-proxies and their allow-list, inbound forwarder(s), run-enclave, store listener
  send-init.sh            init blob over vsock (config, KMS ciphertexts, sealed store from S3)
  send-creds.sh           Bedrock STS credential refresh over vsock (systemd timer, every 20 min)
  nginx-sni-split.conf    the SNI-preread stream block on :443 (and the rollback it keeps),
                          plus the api arm (:8445, proxy_protocol on)
  nginx-pp-arm.conf, nginx-pp-arm-server.conf, install-pp-arm.sh, pp-forwarder.sh
                          the api arm on its own, the installer, and the host-side socat
  renew-cert-dns01.mjs    the CI side of certificate renewal
  renew-azure-cert-dns01.mjs, check-azure-standby-cert.mjs
                          the Azure standby's own certificate for api.ppq.ai, and its expiry check
  lib/                    dns01.mjs (GoDaddy DNS-01 flow shared by both renewals), azureCert.mjs, spki.mjs
  check-live-attestation.mjs, check-drift.py, kms-pcr0-allow.py, ci-ssm-wait.sh
  fleet/                  boot-enclave.sh, create-nlb.sh, create-api-nlb.sh, configure-autoscaling.sh,
                          configure-scaling-alerts.sh (+ scaling-alerts/), scope-host-parameter-access.sh
  systemd/                ppq-enclave.service and the Bedrock creds timer
.github/workflows/        build, cutover, fleet refresh, drift check, certificate renewal (enclave, and the Azure standby)
OPERATIONS.md             the runbook: arms, load balancers, autoscaling, alerts, certificates
DEV-ENCLAVE.md            the dev enclave
REPRODUCE.md              rebuilding the measurement yourself
```

## Testing changes safely

Enclave source changes cannot be tested by unit tests alone: `boot.sh` and the
TLS handshake path only fail when an enclave actually boots or a client
actually connects. There is a **dev enclave** for this, a second Nitro host
with its own hostname and no access to any production secret. See
[DEV-ENCLAVE.md](DEV-ENCLAVE.md). Stop it when you are done; it bills by the
hour.

## Reproducible builds

```bash
# On a Nitro-enabled instance:
./scripts/build-enclave.sh
cat build/PCR.json   # {node_base, go_base, al2_base, debian_snapshot, PCR0, PCR1, PCR2}
```

`build-enclave.sh` pins every input (base images by digest, apt by Debian
snapshot, Go by `go.mod` + `go.sum`, npm by lockfile) and records them next to
the resulting PCR values. Rebuild from a tagged commit → identical `PCR0`.
[REPRODUCE.md](REPRODUCE.md) walks through it and names the two inputs that
are not snapshot-pinned (the `yum` toolchain and the rustup installer in the
`kmstool_enclave_cli` stage).

## Status

**Working, in production:** TLS terminating inside the enclave on both public
names with a browser-trusted certificate; EHBP for browsers; attestation-gated
provider keys; content-free billing; signed routing receipts; a load-balanced,
autoscaling fleet sharing one measurement, one identity and one certificate;
unattended certificate renewal with the key in-enclave; external drift checking
every six hours.

### Known gaps — read before quoting the privacy claim

1. **An unsealed body is accepted silently on the chat and decisions paths.**
   `server.mjs` opens the HPKE seal only when `Ehbp-Encapsulated-Key` is
   present; otherwise it parses the raw body. Attested TLS still protects that
   body from the parent, but only for a client that verified the certificate
   against the attestation. A browser that omits EHBP has no such check and
   gets **no error**. This fails open. (The `private/*` relay is the
   exception: a missing seal there is a 400.)
2. **KMS gating vs. the plaintext fallback.** The image builds
   `kmstool_enclave_cli`, but `boot.sh` falls back to init-channel plaintext
   keys when the ciphertext or the tool is absent or the decrypt fails.
   Confirm which mode a given boot used before claiming attestation-gated
   custody; `/health` answers it per provider under `key_sources`.
3. **The rollback path still exists on every box, and its certificate expires
   on 2026-10-13.** nginx keeps a host-terminated arm (`127.0.0.1:8444`, with
   the old certbot certificate) that one map line and a reload would put
   `enclave.ppq.ai` back on. It is the emergency exit if in-enclave TLS ever
   has to be backed out, and while it is in use the trust property described
   above does not hold. The drift check would report it (served SPKI ≠
   attested SPKI). After the certificate expires the exit is not usable
   without renewing it first.
4. **The external drift check covers `enclave.ppq.ai` only.** It reads the
   healthy targets of that name's target group and connects with that server
   name. `api.ppq.ai`, which carries most traffic, shares the same boxes,
   certificate and image, but is not independently probed from the outside.
5. **The reference clients pin a single `PCR0`.** `client/verify.mjs`,
   `client/browser-verify.mjs` and `client/nitro-secure-fetch.mjs` take one
   expected measurement and do not read `accepted_pcr0`, so during a rollover
   they reject the enclave until re-pinned. The web app's copy honours the
   list; the npm proxy's copy pins `current.pcr0` only.
6. **The trace drops the route for Tinfoil and Venice requests.** `route.chosen`
   is validated against a five-provider enum that predates both, so those
   rows settle without a provider in the trace (the settle row's own
   `provider` field is unaffected).
7. **Metadata is not protected**, and is not claimed to be; see
   [Threat model](#threat-model).

**Also remaining:** signed authorize grants; a byte-reproducible
`kmstool_enclave_cli` stage (see [REPRODUCE.md](REPRODUCE.md)).

### Bedrock direct upstream (api_style: 'bedrock')

OpenAI frontier models served straight from AWS Bedrock inside the enclave,
via the **OpenAI Responses API on the bedrock-mantle endpoint**
(`https://bedrock-mantle.<region>.api.aws/openai/v1/responses`), the only
surface that serves these models (Converse, ConverseStream, InvokeModel and
bedrock-runtime all reject them). horse-power's `/enclave/authorize` offers a
`bedrock` candidate; the enclave runs the shared eligibility gate and
projection first, then `bedrock.mjs` maps the chat body to the Responses
dialect (always `store: false`, because the API persists by default and this
proxy exists so content never rests outside the enclave; `temperature` and
`top_p` are not forwarded), `sigv4.mjs` signs the exact bytes under service
name `bedrock-mantle` with short-lived STS credentials, and the Responses SSE
stream is translated back into chat-completions SSE for the existing
cost/rebrand pipeline (usage passes through verbatim; the cache-write premium
is priced horse-power-side). The path is stream-only. Credentials are
re-delivered by the host every 20 minutes over the persistent vsock `:7001`
channel, KMS-enveloped under the attestation-gated CMK when possible and
plaintext otherwise, with an expiration required either way. Anything missing
(tunnel, credentials, an unmappable field, a non-streaming request) skips the
candidate and the request rides OpenRouter, exactly like the Fireworks path.

### Tinfoil private models (`private/*`): the relay, and the seal on your behalf

The `private/*` models run inside [Tinfoil](https://tinfoil.sh)'s AMD SEV-SNP
confidential VMs, so the model provider is blind as well as PayPerQ. Every
request for them enters this enclave; horse-power no longer handles private
chat. Two classes, told apart by path (both carry `Ehbp-Encapsulated-Key`, so
nothing is sniffed):

| | `POST /private/v1/chat/completions` | a `private/*` model on `POST /v1/chat/completions` |
|---|---|---|
| The body is sealed to | **Tinfoil's** key, by the client (the npm proxy, the Tinfoil SDK, the web app) | this enclave's key (a browser) or nothing (an SDK over attested TLS) |
| The enclave | authorizes on the cleartext headers, **relays the ciphertext**, re-emits `Ehbp-Response-Nonce` and the usage line | **verifies Tinfoil's attestation itself**, strips PayPerQ-only fields (`provider`, `plugins`, `credit_id`, …), seals the body to the attested HPKE key, forwards, opens the reply |
| Who can read the prompt | you, and the model inside Tinfoil's enclave | you, this enclave (briefly, in measured code), and the model inside Tinfoil's enclave |
| Receipt | none: the enclave cannot see what it relays | yes |
| What it buys | horse-power out of the Tinfoil byte path; wire-compatible with every published client | privacy by default for any OpenAI-compatible client, no proxy to install |

On the relay path the model comes from `X-Private-Model` (bare ids get
`private/` prepended; default `private/kimi-k3`), and a request without a seal
is refused with 400 `missing_encryption`.

**Verification is offline and in here.** `@tinfoilsh/verifier` checks the
router's SEV-SNP report against the VCEK carried in the attestation bundle,
the Sigstore provenance of the `tinfoilsh/confidential-model-router` release
against an embedded trusted root, and that the two measurements agree. The
bundle comes from `atc.tinfoil.sh` for the pinned router (`TINFOIL_HOST` in
`tinfoil.mjs`, a measured constant: `inference.tinfoil.sh`, the same router
horse-power's candidate names), through its own control-plane tunnel. The
verified key is cached for an hour per worker and dropped on a key-config
`422` from the router (one re-attest-and-retry, then the router's answer
passes through). A `2xx` from the router with no response nonce is refused
rather than passed on unopened. `/health` shows `tinfoil.verified` and
`measurement`, never the key.

**Never OpenRouter.** horse-power's `/enclave/authorize` answers a `private/*`
model with a single `tinfoil` candidate; `normalizeCandidates` would append the
usual OpenRouter terminal, and for a private prompt that fall would be the leak
the model exists to prevent, so `server.mjs` strips it. A private request that
arrives with no Tinfoil candidate at all is refused with 400
`model_rejected_private_path`; one whose candidate cannot be used (no key, no
tunnel, attestation failed) is refused with 502 `upstream_unreachable`, after a
`tinfoil_attestation_failed` report where that was the cause. It is not
answered elsewhere. `upstreamBinding.mjs` binds `private/` to the Tinfoil host
so horse-power cannot pair it with another provider either, and the converse,
a Tinfoil candidate for a public model, is refused too.

**Billing.** The router's usage line (`X-Tinfoil-Usage-Metrics`: a header on a
JSON answer, a trailer on a stream) carries the counts, the cached count and
the attested served model. The enclave settles `provider: 'tinfoil'` with
those; horse-power prices from the attested model and fails closed to the
dearest private rate when it is not one it knows. The client's
`X-Private-Model` claim never sets the price. A `2xx` with no usage line is
reported as `tinfoil_usage_missing`; on the relay path it still settles a
zero-count row so the request is not lost.

**Key custody.** `TINFOIL_API_KEY` arrives like every other bearer key
(`tinfoil_key_ciphertext`, KMS-gated, with the plaintext init fallback) and is
reported under `key_sources.tinfoil`. The client's own PayPerQ credential never
reaches the router: the relay swaps it for the enclave's key.

What stays with horse-power: `/private/v1/convert/file` (document conversion,
not a chat model) and the legacy `/encrypted/*` and `/tinfoil/*` aliases,
which no published client uses.
