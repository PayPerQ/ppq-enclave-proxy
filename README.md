# ppq-enclave-proxy

A confidential-computing proxy for PayPerQ chat completions. It runs inside an
**AWS Nitro Enclave** so that **PayPerQ can never observe the content** of user
queries. Clients connect **directly** to the enclave; the enclave forwards to
OpenRouter and reports only **billing metadata** (token counts, cost, credit id)
back to PayPerQ's backend.

This repository is **public and its builds are reproducible on purpose**: the
privacy claim only holds if anyone can rebuild this exact source, reproduce the
enclave measurement (`PCR0`), and verify that the running enclave matches. See
[Reproducible builds](#reproducible-builds).

## Threat model

**What this protects:** PayPerQ (the parent EC2 instance, its operators, the
backend, databases, and logs) cannot see query or response content. The parent
instance only ever forwards ciphertext.

**What this does NOT protect:** OpenRouter and the upstream model provider
(Anthropic/OpenAI/Google) still receive plaintext — they must, to run inference.
The guarantee is *"PayPerQ is blind,"* not end-to-end secrecy from every party.
For models that can run fully inside an enclave, see PayPerQ's Tinfoil private
models instead.

The guarantee is only meaningful if the client **verifies attestation** and pins
the expected `PCR0`. A client that skips verification gets no guarantee.

## Architecture

```
client ──TLS──▶ EC2 parent (ciphertext only) ──vsock──▶ ENCLAVE
                                                          • terminates client TLS
                                                          • routing + transforms
                                                          • OpenRouter key via
                                                            attestation-gated KMS
                                                          • calls OpenRouter
                                                          • extracts usage/cost
                                                          • POST /enclave/settle ─▶ horse-power
                                                                                    (metadata only)
```

- **Inbound:** the parent forwards raw client TCP (including the TLS handshake)
  over vsock; TLS **terminates inside the enclave**. The parent holds no TLS key
  and sees no plaintext.
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

## Status

Proof of concept. Not yet production-hardened (no HA/NLB, ephemeral self-signed
TLS cert not yet bound to the attestation document, per-request authorize rather
than signed grants). See the feasibility doc in the PayPerQ workspace for the
full roadmap.
