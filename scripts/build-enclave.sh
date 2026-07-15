#!/usr/bin/env bash
# Build the enclave Docker image and convert it to an EIF, recording the PCR
# measurements. The Dockerfile pins every input (base image digests, go.sum, apt
# snapshot, npm lockfile), so this build is reproducible: run it anywhere, any
# time, and you get the same PCR0. See REPRODUCE.md.
#
# Run on a Nitro-enabled instance (needs docker + nitro-cli). BuildKit is
# disabled for a stable legacy builder (deterministic layer assembly).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/enclave"

IMAGE_TAG="ppq-enclave-proxy:latest"
BUILD_DIR="$REPO_ROOT/build"
mkdir -p "$BUILD_DIR"

echo ">> docker build (inputs are pinned in the Dockerfile)"
DOCKER_BUILDKIT=0 docker build -t "$IMAGE_TAG" .

echo ">> nitro-cli build-enclave"
nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$BUILD_DIR/ppq-enclave-proxy.eif" \
  | tee "$BUILD_DIR/build-output.json"

PCR0="$(jq -r '.Measurements.PCR0' "$BUILD_DIR/build-output.json")"
PCR1="$(jq -r '.Measurements.PCR1' "$BUILD_DIR/build-output.json")"
PCR2="$(jq -r '.Measurements.PCR2' "$BUILD_DIR/build-output.json")"

# The two base digests are pinned in the Dockerfile; record them for the release.
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
