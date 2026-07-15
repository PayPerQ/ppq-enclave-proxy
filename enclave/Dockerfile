# PPQ Enclave Proxy — enclave image
#
# REPRODUCIBLE BUILD. Every input is pinned so that anyone, on any machine, at
# any later date, rebuilds a byte-identical image and therefore the SAME PCR0:
#   - base images pinned by @sha256 digest (not floating tags)
#   - Go deps pinned by committed go.mod + go.sum, built with -mod=readonly
#     (no network resolution)
#   - apt packages pinned to a fixed Debian snapshot (snapshot.debian.org), so
#     the exact same package versions are installed regardless of when you build
#   - Node deps pinned by committed package-lock.json (npm ci)
# Rebuild with scripts/build-enclave.sh and compare the printed PCR0 against
# attestation/PUBLISHED_PCR.md and the value clients pin. If it matches, the
# running enclave is provably built from this exact source. See REPRODUCE.md.

# ── Stage 1: build the NSM attestation helper (Go) ────────────────────────────
FROM golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS attestbuilder
WORKDIR /src/attest
# Deps first (cached) — go.mod + go.sum pin the full module graph by hash.
COPY attest/go.mod attest/go.sum ./
RUN go mod download
COPY attest/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly \
    go build -trimpath -ldflags "-s -w -buildid=" -o /attest .

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

# Pin apt to a fixed Debian snapshot so socat/openssl/jq/iproute2/ca-certificates
# resolve to the exact same versions on every rebuild. The snapshot archive is
# immutable, so this is deterministic forever. (Bump DEBIAN_SNAPSHOT + re-publish
# PCR0 when you intentionally want newer packages.)
ARG DEBIAN_SNAPSHOT=20260701T000000Z
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      socat \
      openssl \
      jq \
      iproute2 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Node deps: committed package-lock.json pins the exact tree by version + hash.
COPY package.json package-lock.json /app/
RUN npm ci --omit=dev --no-audit --no-fund
COPY src/ /app/src/
COPY boot.sh /app/boot.sh
COPY --from=attestbuilder /attest /app/attest
RUN chmod +x /app/boot.sh /app/attest

ENTRYPOINT ["/app/boot.sh"]
