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

# Global build args (must precede the first FROM to be usable in FROM lines).
# ⚠ Pin AL2_DIGEST to a @sha256 digest after the first successful kmstool
# build on the x86 build host (see Stage 1b's reproducibility note).
ARG AL2_DIGEST=public.ecr.aws/amazonlinux/amazonlinux:2

# ── Stage 1: build the NSM attestation helper (Go) ────────────────────────────
FROM golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS attestbuilder
WORKDIR /src/attest
# Deps first (cached) — go.mod + go.sum pin the full module graph by hash.
COPY attest/go.mod attest/go.sum ./
RUN go mod download
COPY attest/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly \
    go build -trimpath -ldflags "-s -w -buildid=" -o /attest .

# ── Stage 1b: kmstool_enclave_cli (attestation-gated KMS decrypt) ─────────────
# Mirrors aws/aws-nitro-enclaves-sdk-c v0.4.2 containers/Dockerfile.al2 with
# every git dependency pinned to that file's exact tags; the SDK itself is
# cloned at v0.4.2 instead of COPY'd. This retires the standing "wire
# in-enclave KMS decrypt" production gap (README) in the same PCR0 bump as the
# Bedrock upstream, which needs it for attestation-gated creds delivery.
#
# ⚠ REPRODUCIBILITY (validate on the x86 build host before publishing PCR0):
#   - BASE and the yum toolchain packages are NOT snapshot-pinned the way the
#     runtime stage's apt is. Pin AL2_DIGEST to the digest of the first
#     successful build; if repeated builds of this stage do not produce
#     byte-identical binaries, DROP this stage and the two COPYs below — the
#     connector's plaintext creds fallback keeps Bedrock functional (equal to
#     today's live key-delivery posture) and kmstool re-pins separately.
FROM ${AL2_DIGEST} AS kmstoolbuilder
RUN yum install -y cmake3 gcc git tar make gcc-c++ go ninja-build && yum clean all
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.63
WORKDIR /tmp/crt-builder
RUN git clone --depth 1 -b v1.12.0 https://github.com/awslabs/aws-lc.git aws-lc \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -DBUILD_TESTING=0 -S aws-lc -B aws-lc/build \
 && go env -w GOPROXY=direct \
 && cmake3 --build aws-lc/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v1.3.46 https://github.com/aws/s2n-tls.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -S s2n-tls -B s2n-tls/build \
 && cmake3 --build s2n-tls/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.8.0 https://github.com/awslabs/aws-c-common.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-common -B aws-c-common/build \
 && cmake3 --build aws-c-common/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.1.2 https://github.com/awslabs/aws-c-sdkutils.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-sdkutils -B aws-c-sdkutils/build \
 && cmake3 --build aws-c-sdkutils/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.5.18 https://github.com/awslabs/aws-c-cal.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-cal -B aws-c-cal/build \
 && cmake3 --build aws-c-cal/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.11.0 https://github.com/awslabs/aws-c-io.git \
 && cmake3 -DUSE_VSOCK=1 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-io -B aws-c-io/build \
 && cmake3 --build aws-c-io/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.2.14 https://github.com/awslabs/aws-c-compression.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-compression -B aws-c-compression/build \
 && cmake3 --build aws-c-compression/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.7.6 https://github.com/awslabs/aws-c-http.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-http -B aws-c-http/build \
 && cmake3 --build aws-c-http/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.6.15 https://github.com/awslabs/aws-c-auth.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-auth -B aws-c-auth/build \
 && cmake3 --build aws-c-auth/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b json-c-0.16-20220414 https://github.com/json-c/json-c.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=OFF -GNinja -S json-c -B json-c/build \
 && cmake3 --build json-c/build --parallel $(nproc) --target install
RUN git clone --depth 1 -b v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git \
 && source $HOME/.cargo/env \
 && cd aws-nitro-enclaves-nsm-api && cargo build --release --jobs $(nproc) -p nsm-lib \
 && mv target/release/libnsm.so /usr/lib64 && mv target/release/nsm.h /usr/include
RUN git clone --depth 1 -b v0.4.2 https://github.com/aws/aws-nitro-enclaves-sdk-c.git \
 && cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
      -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build \
 && cmake3 --build aws-nitro-enclaves-sdk-c/build --parallel $(nproc) --target install

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
 && rm -rf /var/lib/apt/lists/* \
      /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log \
      /var/cache/ldconfig/aux-cache

WORKDIR /app
# Node deps: committed package-lock.json pins the exact tree by version + hash.
# Delete build-time caches/logs afterward — npm's _cacache, npm debug logs, and
# Node's V8 compile cache all have non-deterministic content and would break
# reproducibility (they're not needed at runtime).
ENV NODE_COMPILE_CACHE=""
COPY package.json package-lock.json /app/
RUN npm ci --omit=dev --no-audit --no-fund \
 && rm -rf /root/.npm /tmp/node-compile-cache /tmp/v8-compile-cache* /tmp/* 2>/dev/null || true
COPY src/ /app/src/
COPY boot.sh /app/boot.sh
COPY --from=attestbuilder /attest /app/attest
# kmstool: the AL2-built binary runs on bookworm (glibc forward-compat); its
# only shared deps are libnsm.so + base glibc. s2n's trust store path is baked
# to the AL2 location, so alias bookworm's CA bundle there.
COPY --from=kmstoolbuilder /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
COPY --from=kmstoolbuilder /usr/lib64/libnsm.so /usr/lib/x86_64-linux-gnu/libnsm.so
RUN mkdir -p /etc/pki/tls/certs \
 && ln -s /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt
RUN chmod +x /app/boot.sh /app/attest /usr/bin/kmstool_enclave_cli

ENTRYPOINT ["/app/boot.sh"]
