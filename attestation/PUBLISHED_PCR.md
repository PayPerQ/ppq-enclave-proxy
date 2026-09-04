# Published enclave measurements

Clients pin `PCR0` and refuse to send queries to any enclave whose attestation
document reports a different value. The KMS key policy that releases the
OpenRouter API key is conditioned on the same `PCR0`.

Rebuild from the tagged commit with `./scripts/build-enclave.sh` and confirm you
get the identical `PCR0`. If it matches, the running enclave is provably built
from this source.

## v0.6.0 (2026-09-04) — Anthropic coverage build; image gate, translator residues

Built from `750a4c7` (#71), which carries #60's measured content unchanged.
#60's own build (`546aa9a`, run 33795899570) is the one that died on the full
disk; the rebuild ran after #71 landed, so the tree that was measured is
`750a4c7`. Reproduce against that commit -- `546aa9a` names the change, not the
tree the EIF was built from.

**This release was late, and the delay is the story.** #60 changed measured
paths on 2026-09-03 and its build died because the box had filled its 30GB root
volume (42MB free; ~24GB of reclaimable Docker images and build cache). The
workflow ran `build-enclave.sh 2>&1 | tail -40`, and a pipeline's exit status is
the LAST command's -- `tail`, always 0 -- so SSM reported Success, the build step
went green, and the failure surfaced one step later as a JSON parse error on a
`PCR.json` that was never written. Production stayed a release behind for ~12
hours behind two green-looking steps.

What noticed was the scheduled drift check (#54), red three runs running. Both
holes are now closed in #71: the build re-raises its own exit code, and the
drift check reads the box's disk usage -- a full disk does not merely break the
next build, it means there is no working path to an emergency rollback.

Fifth consecutive zero-downtime rotation. Pre-accepted (#72), convergence
confirmed across sampled instances, #50's guard passed.

CI-attested: run
[33855974811](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33855974811);
`gh attestation verify` passed, and the run's `PCR.json` artifact was
re-downloaded and re-read after publication to confirm the value in this table
is the one the attestation covers. Reproducibility not
independently re-confirmed -- built once, by CI.

`PCR1` unchanged.

| Field | Value |
|---|---|
| Source commit | `750a4c7` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `0c568446e046d0883ebb71d3c1a1f7e8f475e17f775887cb4814a1ef4d99c78761ef86c0e3dd005835c11969f38e7439` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `ba999af94218b5666df54e5f8afd4c2fcd512311a77fa2879991db93c8a41784b4bd9c8b172fa1fa05464d594c4ef136` |

## v0.5.9 (2026-09-03) — signed routing receipts

Built from `82043e0` (#67). Routing receipts are now SIGNED, so they are
trustworthy through an untrusted hop and remain checkable after the fact.
Previously a receipt was only trustworthy inside the EHBP seal, which meant
the web app could rely on it and a plain HTTPS client could not -- nginx
terminates TLS on the public path and could rewrite the body.

NO ATTESTATION FORMAT CHANGE was required. The document already commits to
`user_data = SHA-256(TLS cert SPKI)`, and that keypair is generated in-enclave
by boot.sh and never leaves, so signing with the TLS private key reuses an
existing attested commitment. `/attestation` now also returns `cert_spki_der`
so a browser -- which cannot read a TLS peer certificate -- can obtain the key
to verify against. Serving it is safe because the client must hash it and match
`user_data` inside the NSM-signed document first.

The whole four-step chain was verified against PRODUCTION on this measurement,
not against test keys:

```
step 1  attestation fetched, doc bytes = 4536, cert_spki_der present
step 2  SHA-256(served SPKI) == attestation cert_spki_sha256
step 3  that raw hash is present inside the NSM-SIGNED COSE document
step 4  live receipt signature verifies against the attested key   -> True
        same receipt with api.anthropic.com -> api.fireworks.ai    -> False
```

The negative control is the point: rewriting where the receipt says the request
went breaks the signature.

Fourth consecutive zero-downtime rotation. Pre-accepted (#68), convergence
confirmed, #50's guard passed.

CI-attested: run
[33778501895](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33778501895);
`gh attestation verify` passed before this row was written. Reproducibility not
independently re-confirmed -- built once, by CI.

`PCR1` unchanged.

| Field | Value |
|---|---|
| Source commit | `82043e0` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `e9e4a23d8503d86e90d43e762984141699c55d7b3af8b492e4ddb60d44a9c48c2fd178fd41a8e9c50b396c3e31a6701a` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `266028cbc71cb272f80261cb88c0bb299c9b16ad8cfcf04afa9a7b6094523e87c5722fd0949a6898c9edfce5d10bcfb0` |

## v0.5.8 (2026-09-03) — family-level upstream binding

Built from `67e23a0` (#63). The enclave now REFUSES an upstream the published
map does not permit for the requested model's vendor namespace. `UPSTREAM_PORTS`
already stopped horse-power naming an arbitrary host, but nothing stopped it
pairing `anthropic/*` with `api.fireworks.ai` -- an expensive model on a cheap
provider, invisible to attestation because hp chooses the upstream and carries
no measurement.

Fail-safe: a violating candidate is skipped, never fatal. OpenRouter is
permitted for every family and terminal in every list, so the answer is still
served. Refusals are recorded in the routing receipt and reported through the
content-free error channel.

Verified live after the swap that the map is NOT over-strict -- its failure
mode is silently pushing legitimate traffic onto the OpenRouter margin, which
costs money and raises no error. v0.5.7's receipts were the instrument:

```
anthropic/claude-opus-4.8   route=direct      upstream=api.anthropic.com
google/gemini-3.8-flash     route=direct      upstream=aiplatform.googleapis.com
moonshotai/kimi-k3          route=direct      upstream=api.fireworks.ai
openai/gpt-5.6-luna         route=openrouter  (no candidate offered, not refused)
```

No `upstream_not_bound_to_family` in any receipt, and prod settle data shows
Anthropic, Google and Fireworks all still serving directly after the swap.

Third consecutive zero-downtime rotation. Pre-accepted (#64), convergence
confirmed across sampled instances before the swap, #50's guard passed. Enclave
capture over the window containing both of today's rotations was 1.87%, the
highest of the preceding five 4-hour buckets -- no dip.

CI-attested: run
[33775844182](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33775844182);
`gh attestation verify` passed before this row was written. Reproducibility not
independently re-confirmed -- built once, by CI.

`PCR1` unchanged.

| Field | Value |
|---|---|
| Source commit | `67e23a0` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `3a0d5424a5cd0807158768445f9aaca216bd948a0a7b371e87a34105a7365e3ab3b1f1f57a9fe71bb0ec677e1129defd` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `f1f9ce1140b521e36ca308605bddebd98340f5104191f63660abd412e4cc8dd7d1586a6250001a6f70970c1dda795680` |

## v0.5.7 (2026-09-03) — attested routing receipts

Built from `8a3a291` (#59). The enclave now states, from measured code, where
each request actually went: the host its TLS validated against, the model put
on the wire, direct-vs-OpenRouter, and why earlier candidates were skipped.

This matters because attestation alone never covered it. The enclave does not
choose the upstream -- horse-power does at `/enclave/authorize`, and hp carries
no measurement. Before this the enclave told the client nothing at all, and
`directResponseRewriter` actively hides the wire model id behind the public
slug, so a direct Anthropic request was indistinguishable from an OpenRouter
one. The receipt does not PREVENT substitution; it ends its deniability.
Prevention is #58 phase 3.

Verified live on this measurement:

```
: ppq-routing-receipt {"v":1,"requested_model":"anthropic/claude-haiku-4.5",
  "upstream":"api.anthropic.com","upstream_model":"claude-haiku-4-5",
  "route":"direct","provider":"anthropic","upstream_status":200,
  "skipped":[],"failed":[],"upstream_selects_provider":false}
```

Second consecutive zero-downtime rotation. `5766786f` was pre-accepted (#61),
every sampled instance confirmed serving both measurements before the swap
(~3.5 minutes to converge, against 8-plus before the cache-TTL fix), and #50's
guard passed. Nothing fell back.

CI-attested: run
[33772481760](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33772481760).
`gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy` passed before
this row was written. Reproducibility not independently re-confirmed -- built
once, by CI, as with v0.5.4 through v0.5.6.

`PCR1` unchanged, the expected signature of a source-only change.

| Field | Value |
|---|---|
| Source commit | `8a3a291` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `5766786f65ba74b7e812f5bee64d153af61f10925f803236c46b5c26dea25f88fd04c65e4d435650969a4202022f9526` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `6e3aba13c5502e016823b7dec20af90f695cb972349b684fa23915e8da6f1a49fcafb727931674564e47e688e203ecb6` |

## v0.5.6 (2026-09-03) — reasoning canonicalization in eligibility

Built from `e429c62` (#49, mirroring the reasoning canonicalization into
`eligibility.mjs`).

**First cutover that cost nothing.** Every rotation before this one traded
confidentiality coverage for the swap: clients pinned the outgoing measurement,
so they all fell back to the non-attested path until the frontend caught up —
90 percent to 17 percent capture on 2026-08-24, and 35 minutes of it on
2026-09-02. This one listed the incoming measurement in `accepted_pcr0` first
(#53), let clients pick it up, and only then swapped. Both were accepted across
the window and nothing fell back.

That ordering is now enforced rather than remembered: #50 makes the cutover
refuse to swap to a measurement `published-pcr.json` does not already accept.
The check ran and passed on this rotation.

Attested by CI: run
[33718594632](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33718594632)
emitted Sigstore provenance over the `PCR.json` below. Verify it yourself —
download that run's `PCR.json` artifact and run
`gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy`. A tampered
file or the wrong repo both fail to resolve an attestation.

Every build input except `src/` is unchanged from v0.5.5 — same node, go and AL2
base digests, same Debian snapshot. `PCR1` is therefore identical and only
`PCR0`/`PCR2` move, the expected signature of a source-only change.

As with v0.5.4 and v0.5.5, reproducibility was not independently re-confirmed:
this measurement was built once, by CI. Rebuilding from `e429c62` should yield
the same `PCR0`; that is an expectation here, not a verified result.

| Field | Value |
|---|---|
| Source commit | `e429c62` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `b0d2d76c68250b3e98a12d7e6e1ea80856b9d2be832282ee8895abfbb0285376b3de9f0badecfed45ba74446895db71d` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `3b1f2a89e01197e5faee42140b609b21cc50501e22fdc639d8186088aff51e71ce6c2184eaadf31ba1fba18aae90235b` |

## v0.5.5 (2026-09-03) — Bedrock activation + tool-arg backfill

Built from `45da8a1` (#47 Bedrock activation: cutover creds delivery + refresh
timer, terminal tool-argument backfill in the Responses→chat translator) by CI
run [33701091874](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33701091874).
Every build input except `src/` is unchanged from v0.5.4 — same node, go and
AL2 base digests, same Debian snapshot — so `PCR1` is identical and only
`PCR0`/`PCR2` move, the expected signature of a source-only change.

Deployed by cutover run
[33702309251](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33702309251),
which swapped, initialized, and — for the first time — delivered Bedrock
signing credentials (`bedrockCredsLoaded: true`), then **failed at the smoke
test**: the host's `vsock-proxy 9443 openrouter.ai` died at spawn. Root cause:
every SSM-spawned process lands in `amazon-ssm-agent.service`'s cgroup, whose
`TasksMax=9239` was nearly exhausted by 8 proxies × 1025 threads; during
`run-host.sh`'s retry overlap the first-spawned proxy hit the ceiling
(threadpool `EAGAIN` panic). Fixed by hand over SSM: `TasksMax=32768`
(persistent) + respawned the proxy; smoke then passed and the enclave served
its first production Bedrock request. The frontend pin is completed by this
file — the first re-pin under the published-pcr.json scheme (#45), with
`accepted_pcr0` carrying both measurements for the rollover. **Prune
`e9d01f90…` once the rollover is done.** Hardening follow-up: `run-host.sh`
must verify its proxies survived, and the box's TasksMax wants configuration
management.

| Field | Value |
|---|---|
| Source commit | `45da8a1` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `6854ba1c5e41eebab65fde814b3cff0f48f27dabb2da1764061d16ebd8b101d66d26df1509fd7ebac178702e2ed5c1b4` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `20e33b1e7428c086366dedd7a06031ae5556792c081dae8b47344418f53c1ba2a3faf440dbd119146745149f9327fedd` |

## v0.5.4 (2026-09-02) — Vertex direct upstream

Built from `2271f71` (#39 Vertex direct in the enclave: tunnels, SA-key
provisioning, OAuth minting, reasoning capture).

**First release built by CI rather than by hand.** Every row above was produced
by running `scripts/build-enclave.sh` over SSM manually. The `Enclave build
(PCR0)` workflow had never completed a run — first because the repo had no
Actions secrets at all, then because its SSM waiter gave up after 100 seconds
while the build was still healthy and running (#31, #40). Run
[33664028536](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33664028536)
is the first ever to reach **Publish the result**.

Every build input except `src/` is unchanged from v0.5.3 — same node, go and
AL2 base digests, same Debian snapshot. `PCR1` is therefore identical, and only
`PCR0`/`PCR2` move: the expected signature of a source-only change.

**Reproducibility is not independently re-confirmed for this row.** Rows above
record two clean builds agreeing before publication; this measurement was built
once, by CI. Rebuilding from `2271f71` should yield the same `PCR0` — here that
is an expectation, not a verified result, and it is the one claim this entry
makes less strongly than its predecessors.

Deployed to production by cutover run
[33667863912](https://github.com/PayPerQ/ppq-enclave-proxy/actions/runs/33667863912)
with `skip_repin: true`, so the frontend pin lagged the swap by roughly 35
minutes (18:32Z -> 19:08Z). Clients that verify attestation fell back to the
non-attested path for that window; chat was unaffected. Note also that `main`
moved to `f51c680` (#41) after this build — that commit touches only workflow
files, so the deployed measurement still reflects `main`'s measured content.

| Field | Value |
|---|---|
| Source commit | `2271f71` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `e9d01f90579c62beab6d3d64cebe9a3a136c4901e879a7712c70bd253ddb3304565923968f19b2270285dc0f140881de` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `b8d8e8d4fba6c2a64d2dd91439c6b11602cdcd573da74a0cd12f781b2ee73ae4e80d620eeed09c03a64c35044cadcc95` |

## v0.5.3 (2026-09-01) — Sonnet 5 web-plugin swap, translator guards

**Currently deployed.** Built from `59aeb25` (#32 route Sonnet 5 and `~alias`
Claude ids off the broken web plugin, #33 own-property guards on the Anthropic
translator lookups). Two independent clean builds — separate directories, fresh
clone, `--no-cache` — produced the identical measurements below.

Every build input except `src/` is unchanged from v0.5.2: same node, go and AL2
base digests, same Debian snapshot. `PCR1` is therefore identical and only
`PCR0`/`PCR2` move, which is the expected signature of a source-only change.

#32 is the reason this shipped: `webPluginBreaksModel` matched the `anthropic`
namespace on a substring while `modelHasFastNativeSearch` matched on a prefix,
so a `~anthropic/*` payload was swapped plugin → tool and then straight back.
Both now share `modelNamespace()`. Note the broken-model list **fails open** — a
directive-capable Claude model missing from it keeps the plugin and 400s on
every turn after the first, and turn 1 succeeds either way, so probe a
three-message conversation before assuming a new Claude model is unaffected.

| Field | Value |
|---|---|
| Source commit | `59aeb25` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `8b165ad05ed9c235378c91b12015ea4b6cf56569b693a8ed7da4f6156576a83f356fbf4c1962ffdeb9e5771fbf58974f` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `8e54294521ce493080c253bd9befdcd16b72c4fdbf999f94aa7e241bdcb9c8f234a18e3139c480ce66d46e8056c6b779` |

## v0.5.2 (2026-08-27) — auto-router directive, ZDR direct, error reports, free-model parity

Built from `39fb020` (#25 auto-router allow-list as an `/authorize` directive,
#26 serve `provider.zdr` direct when the row provider is ZDR, #27 build +
cutover workflows, #28 content-free failure reports to horse-power, #30
free-model billing and `tool_choice` strip driven by hp's directive).

**Published retroactively on 2026-09-01, and weaker than every other row here.**
This measurement ran in production from 2026-08-27 until it was replaced by
v0.5.3, but the publish step was missed at the time. The values below are taken
from the build record (`build/PCR.json`) preserved on the build host, not from a
fresh confirming rebuild, and there was no second independent clean build. Treat
it as a historical record of what ran, not as an independently verified
reproducibility claim. Anyone auditing this release should rebuild from
`39fb020` and confirm the `PCR0` matches before relying on it.

`PCR1` matches v0.5.1 and v0.5.3, and the base digests and Debian snapshot are
unchanged across all three, which is consistent with a source-only change.

| Field | Value |
|---|---|
| Source commit | `39fb020` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Go base | `golang@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| AL2 base (kmstool) | `public.ecr.aws/amazonlinux/amazonlinux@sha256:701728f3d079f0ed28ad27368370c8712d09a53d02c6fd89cbf3d8119ef76962` |
| Debian snapshot | `20260701T000000Z` |
| PCR0 | `002a03a6f9ff8f525c6e09e851442d1aa49eb947c133538d845c7700700daefb08ce810a0e0a9f0fd355f46dacb5e2a8` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `2d70c5603712ce58f61b66b22e7bc2bf3cbfc239f86a806b002c0c9516d77f39ac61b22bbeb3febce120fe51de3e2d72` |

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
