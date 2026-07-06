#!/usr/bin/env bash
# Build the enclave Docker image and convert it to an EIF, recording the base
# image digest and the resulting PCR measurements for reproducibility.
#
# Run on the Nitro-enabled parent instance (needs docker + nitro-cli).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/enclave"

IMAGE_TAG="ppq-enclave-proxy:latest"
BUILD_DIR="$REPO_ROOT/build"
mkdir -p "$BUILD_DIR"

echo ">> pinning base image digest"
docker pull node:22-bookworm-slim
BASE_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' node:22-bookworm-slim)"
echo "   base = $BASE_DIGEST"
# Build against the pinned digest for a reproducible image.
sed "s#^FROM node:22-bookworm-slim.*#FROM ${BASE_DIGEST}#" Dockerfile > Dockerfile.pinned

echo ">> docker build"
docker build -f Dockerfile.pinned -t "$IMAGE_TAG" .

echo ">> nitro-cli build-enclave"
nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$BUILD_DIR/ppq-enclave-proxy.eif" \
  | tee "$BUILD_DIR/build-output.json"

PCR0="$(jq -r '.Measurements.PCR0' "$BUILD_DIR/build-output.json")"
PCR1="$(jq -r '.Measurements.PCR1' "$BUILD_DIR/build-output.json")"
PCR2="$(jq -r '.Measurements.PCR2' "$BUILD_DIR/build-output.json")"

jq -n \
  --arg base "$BASE_DIGEST" \
  --arg pcr0 "$PCR0" --arg pcr1 "$PCR1" --arg pcr2 "$PCR2" \
  '{base_image: $base, PCR0: $pcr0, PCR1: $pcr1, PCR2: $pcr2}' \
  > "$BUILD_DIR/PCR.json"

echo ">> measurements:"
cat "$BUILD_DIR/PCR.json"
echo ">> EIF at $BUILD_DIR/ppq-enclave-proxy.eif"
