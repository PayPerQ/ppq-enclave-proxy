# ppq-enclave-proxy

A confidential-computing proxy for PayPerQ chat completions. It runs inside an
**AWS Nitro Enclave** so that **PayPerQ can never observe the content** of user
queries. Clients connect to the enclave endpoint rather than through PayPerQ's
backend — horse-power is never on the byte path and receives only **billing
metadata** (token counts, cost, credit id). Note that the parent EC2 instance
*is* on the byte path for the public endpoint; see
[Architecture](#architecture).

This repository is **public and its builds are reproducible on purpose**: the
privacy claim only holds if anyone can rebuild this exact source, reproduce the
enclave measurement (`PCR0`), and verify that the running enclave matches. See
[Reproducible builds](#reproducible-builds).

## Threat model

**What this protects:** PayPerQ (the parent EC2 instance, its operators, the
backend, databases, and logs) cannot see query or response **content** —
*provided the client seals its request body with EHBP*. On the public
`enclave.ppq.ai` path the parent terminates the client's TLS, so the HPKE seal,
**not** the network topology, is what makes the host blind. See
[Architecture](#architecture).

**What the parent sees on that path, always:** the client IP and every request
header, including `x-credit-id` / `Authorization` and `x-query-source`. Only the
body is sealed. There is no unlinkability claim — the host can tie an account to
a timestamp, model, and response size; it just cannot read the content.

**What this does NOT protect:** OpenRouter and the upstream model provider
(Anthropic/OpenAI/Google) still receive plaintext — they must, to run inference.
The guarantee is *"PayPerQ is blind,"* not end-to-end secrecy from every party.
For models that can run fully inside an enclave, see PayPerQ's Tinfoil private
models instead.

The guarantee is only meaningful if the client **verifies attestation** and pins
the expected `PCR0`. A client that skips verification gets no guarantee.

## Architecture

There are **two inbound paths and they do not have the same trust properties.**

### A. Public path — `https://enclave.ppq.ai` (web app + npm package)

```
browser / npm client              EC2 parent (untrusted)                ENCLAVE
   │                        ┌───────────────────────────────┐
   │  TLS #1 ──────────────▶│ nginx :443                    │
   │  headers: CLEARTEXT    │   holds the Let's Encrypt      │
   │  body:    HPKE-sealed  │   private key and TERMINATES   │
   │           (EHBP)       │   TLS #1                       │
   │                        │        │                       │
   │                        │        │ TLS #2 — re-encrypted  │
   │                        │        ▼ to an ephemeral        │
   │                        │ socat :8443 ──vsock:16──────────▶ terminates TLS #2
   │                        └───────────────────────────────┘   opens the EHBP seal
   │                                                            routing + transforms
   │                                                            OpenRouter key via
   │                                                              attestation-gated KMS
   │                                                            calls the upstream
   │                                                            extracts usage/cost
   │                                                            POST /enclave/settle ─▶ horse-power
   │                                                                                    (metadata only)
```

**The parent decrypts TLS #1.** It sees the request headers and an opaque sealed
body. The enclave's attested TLS key is *not* the key the client negotiates
with — that is a property of this topology, not an accident. Confirm it in ten
seconds:

```bash
curl -s "https://enclave.ppq.ai/attestation?nonce=$(openssl rand -hex 16)" | jq -r .cert_spki_sha256
echo | openssl s_client -connect enclave.ppq.ai:443 -servername enclave.ppq.ai 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
# The two values DIFFER. Host-blindness on this path rests entirely on EHBP.
```

### B. Direct path — `:8443` (reference verifier only)

```
client ──TLS──▶ EC2 parent: socat, raw TCP only ──vsock──▶ ENCLAVE terminates client TLS
```

Here TLS genuinely terminates inside the enclave, the parent holds no key for
it, and the attestation's `user_data` pins that exact endpoint. This is what
`client/verify.mjs` uses. The cert is ephemeral and self-signed, so browsers
reject it, and the security group limits :8443 to a single operator IP — it is
**not** a production path.

Moving the public path onto this model requires ACME inside the enclave (so the
browser-trusted private key is generated and held there) plus L4 passthrough in
place of nginx. Until then, treat "TLS terminates in the enclave" as true of
path B only.
- **Outbound:** the enclave reaches OpenRouter, KMS, and horse-power through
  host-side `vsock-proxy` hops. TLS to each is validated end-to-end against its
  real hostname; the proxy blindly forwards bytes.
- **Key custody:** the OpenRouter API key is KMS-encrypted. `kms:Decrypt` is
  gated on `kms:RecipientAttestation:PCR0`, so KMS releases the key **only** to
  an enclave whose measurement matches the published image. PayPerQ operators
  cannot extract it.
- **Billing:** the enclave never writes to the database. It reports token counts
  and cost to horse-power `POST /enclave/settle` (idempotent by `request_id`),
  which applies the margin and debits credits. `queries_metadata` stores no
  content — same as PayPerQ's existing pipeline.

## Layout

```
enclave/
  src/
    server.mjs   # TLS server, OpenRouter forward, streaming, settle callback
    routing.mjs  # model resolution + provider transforms (port of chatPayload.ts)
    cost.mjs     # streaming usage/cost extractor (port of streamParser.ts)
    rebrand.mjs  # OPENROUTER -> PPQ.AI in the response stream
  boot.sh        # in-enclave entrypoint: tunnels, KMS decrypt, TLS cert, exec
  Dockerfile     # pinned base; std-lib only (no third-party npm deps)
scripts/
  build-enclave.sh  # docker build -> nitro-cli build-enclave, records PCR.json
  run-host.sh       # host vsock-proxies + inbound forwarder + run-enclave
  send-init.sh      # one-shot init blob (config + KMS creds/ciphertext) over vsock
  send-creds.sh     # Bedrock STS creds refresh over vsock:7001 (systemd timer, ~30min)
```

## Reproducible builds

```bash
# On a Nitro-enabled instance:
./scripts/build-enclave.sh
cat build/PCR.json   # {base_image, PCR0, PCR1, PCR2}
```

`build-enclave.sh` pins the base image to its `@sha256` digest before building
and records it next to the resulting PCR values. A release publishes `PCR0`; the
KMS key policy and clients both pin that value. Rebuild from a tagged commit →
identical `PCR0`.

## Scope (v1 / PoC)

Streaming chat completions through OpenRouter only. AutoClaw/AutoRouter
smart-routing models, server-side tools (web-retrieval, deep research), and the
browser attestation-verifier UI are follow-ups. `private/*` (Tinfoil) models are
rejected — they use their own path.

## Verifying the enclave (replaces `curl -k`)

The privacy guarantee only holds if the client checks attestation *before*
sending a query. The enclave exposes `GET /attestation?nonce=<hex>`, returning an
AWS-signed (Nitro Security Module) COSE_Sign1 document that echoes the nonce and
commits to **both** key materials:

| Field | Contents | Who uses it |
|---|---|---|
| `public_key` | the enclave's **HPKE (EHBP) public key** | path A — browsers and the npm package seal the body to it |
| `user_data` | **SHA-256 of the TLS cert SPKI** | path B — programmatic clients that can read the peer cert pin the endpoint |

Path A must bind to `public_key`: **browser JavaScript cannot read a TLS peer
certificate**, so a page can never check `user_data` against the connection it is
actually using. That is why EHBP exists and why it is not redundant with TLS.

The reference client in [`client/`](client/) does the full check and only then
sends the request:

```bash
cd client && npm install
node verify.mjs --host <enclave-ip> --port 8443 \
  --expect-pcr0 <published-PCR0> --credit-id <ppq-credit-id>
```

It (1) fetches the TLS cert, (2) fetches the attestation over a pinned
connection, (3) verifies the COSE signature, (4) verifies the certificate chain
up to the pinned **AWS Nitro root** (`client/aws-nitro-root-g1.pem`), (5) checks
validity windows, (6) checks the nonce, (7) checks **PCR0 == the published code
fingerprint**, and (8) checks the attestation is **bound to the TLS cert**. Any
failure aborts before a single byte of the query is sent. This is what turns
"the code is in the TEE" into "the client can *prove* the code is in the TEE."

## Status

**Working:** host-blind proxying (via EHBP on path A), TLS-in-enclave on path B,
content-free billing, client-verifiable attestation (`/attestation`, the
reference verifier, and the browser verifier now shipped in the web app), and a
real domain with a browser-trusted cert.

### Known gaps — read before quoting the privacy claim

1. **Public TLS terminates on the parent, not in the enclave.** nginx holds the
   `enclave.ppq.ai` Let's Encrypt private key. Path A's guarantee comes from the
   EHBP seal alone. Closing this needs in-enclave ACME + L4 passthrough.
2. **An unsealed body is accepted silently.** `server.mjs` opens the HPKE seal
   only when `Ehbp-Encapsulated-Key` is present; otherwise it JSON-parses the raw
   body. A client that omits EHBP loses host-blindness and gets **no error** —
   this fails open. Any claim about a given request holding depends on that
   header being there.
3. **No automated certificate renewal.** The host has no certbot timer or cron
   entry; the cert is renewed by hand. Check the expiry before it bites:
   `echo | openssl s_client -connect enclave.ppq.ai:443 2>/dev/null | openssl x509 -noout -enddate`
4. **KMS gating vs. the plaintext fallback.** The image builds
   `kmstool_enclave_cli`, but `boot.sh` falls back to init-channel plaintext keys
   when the ciphertext or the tool is absent, and the documented `send-init.sh`
   recipe supplies `*_PLAINTEXT` values. Confirm which mode a given boot actually
   used before claiming attestation-gated key custody.

**Also remaining:** commit `go.sum` for a byte-reproducible build; HA/NLB (must
be L4 passthrough — an ALB or any TLS-terminating edge breaks the trust claim);
signed authorize grants. See the feasibility doc in the PayPerQ workspace.

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
