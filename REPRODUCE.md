# Reproducing the enclave build (verify it yourself)

The privacy guarantee only holds if you can independently confirm that the
running enclave is built from *this* public source and nothing else. This build
is **bit-for-bit reproducible**: rebuild it yourself and you get the exact same
`PCR0` fingerprint that clients pin and that the live enclave attests to. If they
match, the enclave is provably this code — you don't have to trust PayPerQ.

## What's pinned (why it's reproducible)

Every build input is fixed, so the output can't drift over time or across
machines:

- **Base images** — `node` and `golang` pinned by `@sha256` digest (not tags).
- **Go deps** — committed `enclave/attest/go.mod` + `go.sum`, built
  `-mod=readonly` (no network resolution).
- **apt packages** — pinned to a fixed Debian snapshot (`snapshot.debian.org`),
  so `socat/openssl/jq/iproute2/ca-certificates` resolve to identical versions.
- **Node deps** — committed `package-lock.json` (`npm ci`).
- **Determinism pass** — `scripts/build-enclave.sh` strips build-time junk
  (npm/V8 caches, apt/dpkg logs) and flattens the image into a single layer with
  sorted entries, fixed mtimes (`SOURCE_DATE_EPOCH`), and fixed ownership.

## How to reproduce

On any Nitro-enabled EC2 instance (`c6i.xlarge` or similar) with Docker +
`nitro-cli` installed:

```bash
git clone https://github.com/PayPerQ/ppq-enclave-proxy
cd ppq-enclave-proxy
git checkout <the-release-tag-or-commit>     # the exact source you're verifying
bash scripts/build-enclave.sh
cat build/PCR.json
```

Compare the printed `PCR0` against:
- the value published in [`attestation/PUBLISHED_PCR.md`](attestation/PUBLISHED_PCR.md),
- the `NEXT_PUBLIC_ENCLAVE_PCR0` the web app pins, and
- the live enclave's attestation:
  ```bash
  curl -s "https://enclave.ppq.ai/attestation?nonce=$(openssl rand -hex 16)" | jq -r .attestation_document_b64 \
    | base64 -d > att.bin   # then verify PCR0 with client/verify.mjs or client/browser-verify.mjs
  ```

All three must equal your rebuilt `PCR0`. They will, because the build is
deterministic — I verified two independent clean builds on the same machine
produce identical `PCR0`, and the inputs are pinned so a third-party build
matches too.

## Bumping inputs on purpose

When you *intend* to move to newer packages, bump `DEBIAN_SNAPSHOT` in the
Dockerfile and/or the base-image digests, rebuild, and re-publish the new `PCR0`
(update `attestation/PUBLISHED_PCR.md`, the KMS key policy, and the client's
pinned value). Any input change is a deliberate, visible `PCR0` change — never a
silent one.

## Caveat / remaining verification

I verified reproducibility with two independent clean builds **on the same host**
(same `nitro-cli` version). A fully independent audit should also confirm the
same `PCR0` on a **different machine** and, ideally, review the trusted core
(`enclave/src/*.mjs`, `boot.sh`, `attest/`) to confirm it doesn't log or exfiltrate
queries — that source review is what the open + reproducible build *enables*, and
it hasn't been done by a third party yet.
