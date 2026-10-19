#!/usr/bin/env bash
# Refuse to measure anything the published commit does not contain.
#
# PCR0 is a hash over the image, and the image is built from the files under
# enclave/ that the Dockerfile COPYs. The build box is persistent and the CI
# sync step used to run `git fetch && git reset --hard $SHA` with no `git clean`,
# so a stray file left under enclave/src/ or enclave/attest/ (a debugging patch,
# an editor backup, anything) would have been copied into the image and
# measured, and the published PCR0 would no longer be a function of the
# published source. Nothing checked for that. Reported in the Oct 17-19
# security batch (Galih Saptahadi, "Reproducible build: the CI sync has no git
# clean ...").
#
# This script is the check, used in three places:
#   - the CI sync step runs it with --clean right after `git reset --hard`;
#   - scripts/build-enclave.sh runs it (check only) before `docker build`, so a
#     local reproduction is held to the same rule as CI;
#   - REPRODUCE.md tells a verifier to run it.
#
# Scope is the MEASURED CONTEXT: exactly the paths the Dockerfile reads, plus
# the files that decide what it reads. Not all of enclave/ -- a developer's
# enclave/node_modules (tests) or enclave/tls (local TLS) never enter the
# image (enclave/.dockerignore is a whitelist of the same paths), so flagging
# them would only teach people to set the override. Keep this list, the
# .dockerignore exceptions and the Dockerfile's COPY lines in step; the test
# enclave/test/buildContext.test.mjs asserts they agree.
#
# Usage: scripts/check-build-context.sh [--clean]
#   --clean   first remove untracked and ignored files under the measured paths
#             (`git clean -ffdx`: the second -f also removes a nested git
#             repository someone left under src/), then check. For the build
#             box, never for a developer's tree without looking.
# Exit 0 when the measured context is exactly the committed tree, 1 otherwise.
# ALLOW_DIRTY_BUILD_CONTEXT=1 turns the failure into a warning (local
# experiments only; a measurement produced that way must never be published).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The Docker build context is enclave/ (build-enclave.sh runs `docker build .`
# from there). These are the paths the Dockerfile COPYs from it, plus the
# Dockerfile itself and the .dockerignore that shapes the context.
MEASURED_CONTEXT=(
  enclave/attest
  enclave/kmstool
  enclave/src
  enclave/boot.sh
  enclave/package.json
  enclave/package-lock.json
  enclave/Dockerfile
  enclave/.dockerignore
)

# Docker reads `<Dockerfile>.dockerignore` IN PREFERENCE to `.dockerignore`
# when both exist (docs.docker.com/build/concepts/context). The repository has
# no such file and must never grow one, tracked or not: left on the build box
# it would replace the whitelist above without touching any measured path.
# Removed by --clean, refused by the check. (Not in MEASURED_CONTEXT: that
# list is "paths that exist and must be clean"; this one must not exist.)
FORBIDDEN_OVERRIDES=(
  enclave/Dockerfile.dockerignore
)

CLEAN=0
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=1 ;;
    --list) printf '%s\n' "${MEASURED_CONTEXT[@]}"; exit 0 ;;
    *) echo "usage: $0 [--clean] [--list]" >&2; exit 2 ;;
  esac
done

cd "$REPO_ROOT"

# CI runs build-enclave.sh as root over an ec2-user-owned checkout; without
# this git refuses with "dubious ownership" (the fleet-refresh workflow sets
# the same thing). Harmless where the owner matches.
GIT=(git -c "safe.directory=$REPO_ROOT")

if [ "$CLEAN" = 1 ]; then
  echo ">> removing untracked and ignored files from the measured build context"
  "${GIT[@]}" clean -ffdx -- "${MEASURED_CONTEXT[@]}"
  rm -f -- "${FORBIDDEN_OVERRIDES[@]}"
fi

for f in "${FORBIDDEN_OVERRIDES[@]}"; do
  if [ -e "$f" ]; then
    echo "!! $f exists: docker would read it instead of enclave/.dockerignore" >&2
    if [ "${ALLOW_DIRTY_BUILD_CONTEXT:-0}" != 1 ]; then
      echo "!! run: rm -- $f" >&2
      exit 1
    fi
    echo "!! ALLOW_DIRTY_BUILD_CONTEXT=1: building anyway; do NOT publish this measurement" >&2
  fi
done

# `--porcelain --ignored` lists modified tracked files (" M"), untracked ("??")
# and ignored ("!!") paths alike: every one of them is bytes the published
# commit does not contain.
DIRTY="$("${GIT[@]}" status --porcelain --ignored -- "${MEASURED_CONTEXT[@]}")"
if [ -n "$DIRTY" ]; then
  echo "!! the measured build context differs from the committed tree:" >&2
  printf '%s\n' "$DIRTY" >&2
  if [ "${ALLOW_DIRTY_BUILD_CONTEXT:-0}" = 1 ]; then
    echo "!! ALLOW_DIRTY_BUILD_CONTEXT=1: building anyway; do NOT publish this measurement" >&2
    exit 0
  fi
  echo "!! run: git clean -ffdx -- $(printf '%s ' "${MEASURED_CONTEXT[@]}")" >&2
  echo "!! (or ALLOW_DIRTY_BUILD_CONTEXT=1 for a local experiment)" >&2
  exit 1
fi
echo ">> measured build context is clean at $("${GIT[@]}" rev-parse --short HEAD)"
