# Published enclave measurements

Clients pin `PCR0` and refuse to send queries to any enclave whose attestation
document reports a different value. The KMS key policy that releases the
OpenRouter API key is conditioned on the same `PCR0`.

Rebuild from the tagged commit with `./scripts/build-enclave.sh` and confirm you
get the identical `PCR0`. If it matches, the running enclave is provably built
from this source.

## v0.5.1 (2026-08-20) — adaptive thinking + web-search interlock

Built from `947e1fb` (#22 reasoning_effort → thinking, #23 adaptive-only
thinking shape, neutral `web_search` detection, `plugins`/`data_source` into
`IGNORED_FIELDS`). Two independent clean builds — separate directories, fresh
clone, `--no-cache` — produced the identical measurements below.

Every build input except `src/` is unchanged from v0.5.0: same node, go and AL2
base digests, same Debian snapshot. `PCR1` is therefore identical and only
`PCR0`/`PCR2` move, which is the expected signature of a source-only change.

Two behaviours in this build are coupled and must ship together: `plugins` is
now ignorable, so the enclave itself has to recognise the neutral
`tools:[{type:'web_search'}]` the app emits — otherwise an Auto-mode search
would reach a direct provider that drops the tool and answers with no results
and no error. Both landed in #23.

| Field | Value |
|---|---|
| Source commit | `947e1fb` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `fc23c3b975b4eb8c190d750dc49104124c8a84e7d3d39cd92facb29b8e5727aaa0369e863b696d7218b405ef64c605d4` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `2ba31bd8086d42303498a96a7ef9e08a0e1a58eb93f9ade3dde4ee15796a5582cabe1f43f2ede49b538ecf1320e02613` |

## v0.5.0 (2026-08-19) — direct Anthropic + Bedrock upstreams, kmstool

Built from `1aacd5a` (#17 Bedrock direct, #18 Anthropic direct, #19 AL2 base
digest pin). Two things make this release different from every row above:

1. **First release whose keys are released by attestation-gated KMS.** Earlier
   builds shipped without `kmstool_enclave_cli`, so the running enclave took its
   upstream keys from the init channel in plaintext. This build decrypts them
   in-enclave, gated on the `PCR0` below in the CMK key policy — verified live.
2. **Reproducibility re-confirmed on the new build inputs.** Two independent
   clean builds (separate directories, fresh clone, `--no-cache`) produced the
   identical `PCR0`/`PCR1`/`PCR2` below. Note the EIF *files* differ byte-wise
   between the two builds — that is unmeasured EIF container metadata; the
   measurements are what attestation covers.

Added as part of the cut-over rather than retroactively, unlike v0.4.1.

Caveat worth carrying forward: the `kmstool_enclave_cli` stage still resolves
some inputs at build time that are not immutable (git clones follow *tags*,
rustup is fetched live, and `yum` resolves from live AL2 repos). The digest pin
in #19 closed the last floating `FROM`, but full long-term reproducibility is
tracked in issue #20. Always confirm two clean builds agree before publishing.

| Field | Value |
|---|---|
| Source commit | `1aacd5a` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `4a237681c62aa46938e4aabad4ebff881c7ee40803ef5102cd79a86d43fde44372af6ca6aa6bd957ef8db4c2f5e58bcd` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `6dd40b2df22198c30b3b517fd86a5347340796f503bc3292dd0450218a3c0cc29c47f2a7015c5c4610bb1764340ac1e4` |

## v0.4.1 (2026-08-13) — web-search eligibility port

Built from `dae4701` ("Force OpenRouter for web-search in eligibility") — a
`src/`-only change; every build input (bases, Debian snapshot, deps) is
identical to v0.4.0. This row was added retroactively on 2026-08-14: the build
went live and the client pins moved (`NEXT_PUBLIC_ENCLAVE_PCR0` on Vercel,
`DEFAULT_ENCLAVE_PCR0` in ppq-private-mode-proxy `feat/nitro-enclave-backend`)
without the registry gaining its row, which broke the "published == pinned ==
live" three-way check this file exists for. Measurements below were read from
the LIVE attestation (`/attestation`, 2026-08-14) and the PCR0 cross-checked
against both client pins; reproduce it from source with
`bash scripts/build-enclave.sh` at `dae4701`.

| Field | Value |
|---|---|
| Source commit | `dae4701` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `304795d4e499f5e8e5b5b77f5f254f1766bff413318b29a84b022579fcec9cace74df1f71bf9102a8da8eda828510633` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `2960d280884c07125caf5a4584250b9f6a82c313d481b1054dc05f69fa99f3dabab73d0b4c7d66cbf87f34ff1c0c18eb` |

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
