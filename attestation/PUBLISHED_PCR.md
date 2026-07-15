# Published enclave measurements

Clients pin `PCR0` and refuse to send queries to any enclave whose attestation
document reports a different value. The KMS key policy that releases the
OpenRouter API key is conditioned on the same `PCR0`.

Rebuild from the tagged commit with `./scripts/build-enclave.sh` and confirm you
get the identical `PCR0`. If it matches, the running enclave is provably built
from this source.

## v0.4.0 (2026-07-15) — REPRODUCIBLE build

First bit-for-bit reproducible release: two independent clean builds produce the
identical PCR0 below. Rebuild it yourself with `bash scripts/build-enclave.sh`
and confirm the match — see [REPRODUCE.md](../REPRODUCE.md). This is what makes
the PCR0 a *verifiable* trust anchor rather than "trust us."

| Field | Value |
|---|---|
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `d08345a22d2f263b4f1a5eff7562dc55914b353306b7a339267b8eff2128230f1e86b5e725b5e540872ad2ebf46cce44` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `593fbc95846ab96449a5df429a8cf4da0f39f95fd25335cb5ccf5b9a58b0a872a4f772c1248ace00312e56a8c7aea5e7` |

Note: the flatten/normalize step preserves `PATH`/`WORKDIR`/`ENTRYPOINT` on the
imported image (an earlier repro build broke boot by dropping `ENV`).

## v0.3.0-poc (2026-07-07) — code-review fixes

Adds: verifier CA-basicConstraints + COSE-alg enforcement, per-request
authorization gate before spending the key, routing synced to current source,
carry-buffer rebrand. Verify with `client/verify.mjs --expect-pcr0 <below>`.

| Field | Value |
|---|---|
| Base image | `node@sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf` |
| PCR0 | `429e6143c4c4e0fe1d4cadab3bde5f14838274350751a5ca448aff4031d66cea0bf223e059d16074eb47bd4afac7f6e3` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `51afeef1043f4013ddab3833a880a3f86cb4061edd3d4054e1f0d917658262823559dfb94b52b132e314b6158714dd00` |

## v0.2.0-poc (2026-07-07) — adds hardware attestation

Run in **production mode** (no `--debug-mode`, so PCRs are real, not zeroed).
Verify with the reference client:

```bash
cd client && npm install
node verify.mjs --host <enclave-ip> --port 8443 \
  --expect-pcr0 2d26a439e86597933a4721ae85f84b30de744e922a9f12c5dec4955d0824a2a22f3f12b4f54387fb1ff480bb30f6a5b4 \
  --credit-id <ppq-credit-id>
```

| Field | Value |
|---|---|
| Base image | `node@sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4` |
| PCR0 | `2d26a439e86597933a4721ae85f84b30de744e922a9f12c5dec4955d0824a2a22f3f12b4f54387fb1ff480bb30f6a5b4` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `29f2aaf51dbba870a8b012a62b7704c51d20bf850919bf14f9d40ed17980f212588f2d9c8fb9fee04d7a1ca50df338c9` |

> Reproducibility caveat: the Go attestation helper is fetched at build time
> (`go get github.com/hf/nsm`) without a committed `go.sum`, so a clean-room
> rebuild is not yet byte-identical. Committing `go.sum` + pinning the module
> version is a required step before this PCR0 is used as a production trust
> anchor.

## v0.1.0-poc (2026-07-06)

| Field | Value |
|---|---|
| Base image | `node@sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4` |
| PCR0 | `ff9d11db1da0cd48589676cb5950ae3d86b6cf21ca41ce3832ab3e96a50fa4596c4fa2c33388dc37c66e898643f0ff05` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `550f9e5093d95c709b357ef1138cb933f147cff9a34ed038929021beb1ad44189b6a890009ea871b60658e1337b7f470` |

> PoC caveat: `PCR1` (kernel/bootstrap) is shared across enclaves built with the
> same nitro-cli; `PCR0` (the full image) and `PCR2` (application) are the
> identity that matters here. This measurement was produced on the reference
> build instance; a clean-room rebuild verification is a follow-up before any
> production trust decision relies on it.
