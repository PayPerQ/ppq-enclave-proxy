# Published enclave measurements

Clients pin `PCR0` and refuse to send queries to any enclave whose attestation
document reports a different value. The KMS key policy that releases the
OpenRouter API key is conditioned on the same `PCR0`.

Rebuild from the tagged commit with `./scripts/build-enclave.sh` and confirm you
get the identical `PCR0`. If it matches, the running enclave is provably built
from this source.

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
