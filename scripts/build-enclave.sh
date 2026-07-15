#!/usr/bin/env bash
# Build the enclave Docker image and convert it to an EIF — reproducibly.
#
# Every build input is pinned in the Dockerfile (base digests, go.sum, apt
# snapshot, npm lockfile). This script then FLATTENS the built image and
# normalizes it into a single deterministic layer (sorted entries, fixed mtimes,
# fixed ownership) before handing it to nitro-cli. The result: run this anywhere,
# any time, and you get the SAME PCR0. See REPRODUCE.md.
#
# Run on a Nitro-enabled instance (needs docker + nitro-cli).
set -euo pipefail

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"   # 2024-01-01, fixed
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/enclave"

IMAGE_TAG="ppq-enclave-proxy:latest"
BUILD_TAG="ppq-enclave-proxy:build"
BUILD_DIR="$REPO_ROOT/build"
ROOTFS="$(mktemp -d)"
mkdir -p "$BUILD_DIR"

echo ">> docker build (inputs pinned in the Dockerfile)"
DOCKER_BUILDKIT=1 docker build --no-cache -t "$BUILD_TAG" .

echo ">> flatten + normalize into one deterministic layer"
cid="$(docker create "$BUILD_TAG")"
docker export "$cid" | tar -xf - -C "$ROOTFS"
docker rm "$cid" >/dev/null
# Normalize every timestamp to the fixed epoch (COPY'd + npm files otherwise keep
# their build-time mtimes, which is the #1 source of PCR0 drift).
find "$ROOTFS" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true
# Deterministic tar: sorted names, fixed mtime, fixed owner, no atime/ctime.
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --numeric-owner --owner=0 --group=0 \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "$ROOTFS" -cf "$BUILD_DIR/rootfs.tar" .
docker import --change 'ENTRYPOINT ["/app/boot.sh"]' "$BUILD_DIR/rootfs.tar" "$IMAGE_TAG" >/dev/null
rm -rf "$ROOTFS" "$BUILD_DIR/rootfs.tar"

echo ">> nitro-cli build-enclave"
nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$BUILD_DIR/ppq-enclave-proxy.eif" \
  | tee "$BUILD_DIR/build-output.json"

PCR0="$(jq -r '.Measurements.PCR0' "$BUILD_DIR/build-output.json")"
PCR1="$(jq -r '.Measurements.PCR1' "$BUILD_DIR/build-output.json")"
PCR2="$(jq -r '.Measurements.PCR2' "$BUILD_DIR/build-output.json")"
NODE_BASE="$(grep -oE 'node:22-bookworm-slim@sha256:[0-9a-f]+' Dockerfile | head -1)"
GO_BASE="$(grep -oE 'golang@sha256:[0-9a-f]+' Dockerfile | head -1)"

jq -n \
  --arg node "$NODE_BASE" --arg go "$GO_BASE" \
  --arg pcr0 "$PCR0" --arg pcr1 "$PCR1" --arg pcr2 "$PCR2" \
  '{node_base: $node, go_base: $go, PCR0: $pcr0, PCR1: $pcr1, PCR2: $pcr2}' \
  > "$BUILD_DIR/PCR.json"

echo ">> measurements:"
cat "$BUILD_DIR/PCR.json"
echo ">> EIF at $BUILD_DIR/ppq-enclave-proxy.eif"
