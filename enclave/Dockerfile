# PPQ Enclave Proxy — enclave image
#
# Reproducibility notes:
#   - Base image is pinned by DIGEST (not a floating tag) so the same build
#     inputs produce the same layers and therefore the same EIF / PCR0.
#   - No `npm install` at build time: the app uses only the Node standard
#     library, so there are no third-party deps to resolve non-deterministically.
#   - Anyone can rebuild from this repo, run `nitro-cli build-enclave`, and
#     compare the printed PCR0 against the value pinned in the KMS key policy and
#     in clients. If it matches, the running enclave is provably this source.
#
# ── Stage 1: build the NSM attestation helper (Go) ────────────────────────────
# Talks to /dev/nsm inside the enclave to fetch a hardware-signed attestation
# document. Static binary, copied into the runtime image below.
FROM golang:1.23-bookworm AS attestbuilder
WORKDIR /src/attest
COPY attest/ ./
RUN GOFLAGS=-mod=mod GOSUMDB=off go get github.com/hf/nsm \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -buildid=" -o /attest .

# ── Stage 2: runtime image ────────────────────────────────────────────────────
# scripts/build-enclave.sh rewrites the tag below to a @sha256 digest before
# building, and records that digest in build/PCR.json alongside the resulting
# PCR0 — so a published release always names the exact base image it used.
#   docker inspect --format='{{index .RepoDigests 0}}' node:22-bookworm-slim
FROM node:22-bookworm-slim

# socat (vsock<->tcp tunnels), openssl (ephemeral TLS cert), jq (parse init blob),
# iproute2 (bring up lo). ca-certificates for outbound TLS trust.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      socat \
      openssl \
      jq \
      iproute2 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ /app/src/
COPY boot.sh /app/boot.sh
COPY --from=attestbuilder /attest /app/attest
RUN chmod +x /app/boot.sh /app/attest

ENTRYPOINT ["/app/boot.sh"]
