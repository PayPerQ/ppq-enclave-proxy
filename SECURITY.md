# Security Policy

This repository is the code that runs inside PayPerQ's production AWS Nitro
enclave and serves every chat request on ppq.ai and api.ppq.ai. Its purpose is
to make a privacy claim that does not depend on trusting PayPerQ. A bug here
can break that claim, so we treat security reports as the highest-priority
work in the repo.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security bug.**

Report privately through either channel:

- **GitHub private vulnerability reporting:** use the "Report a vulnerability"
  button on the Security tab of this repository.
- **Email:** matt@ppq.ai. No PGP key is published yet; ask in your first
  email if you need an encrypted channel and we will set one up.

Include what you can of: the affected file or component, the version or PCR0
you tested against, steps to reproduce, and what you believe the impact is.
A proof of concept is welcome but not required.

## What to expect from us

- **Acknowledgement within 2 business days.**
- A first assessment of severity and an intended fix path within
  7 days.
- Progress updates at least weekly until the report is closed.
- Fix targets: issues that break the privacy or routing guarantee are our
  top priority and we aim to ship a fix within 30 days. Lower-severity
  issues are scheduled on their merits and we will tell you the target.

A fix to the measured code (`enclave/src`, `boot.sh`, `Dockerfile`) ships as a
new enclave image with a new PCR0. Rotation steps are in `OPERATIONS.md`; the
new measurement is published in `attestation/published-pcr.json` and
`attestation/PUBLISHED_PCR.md`. The old measurement is removed from
`accepted_pcr0` once the rollover completes, so verifying clients stop
accepting the vulnerable image.

## Coordinated disclosure

We ask for 90 days from the date of the report, or until a fix is
deployed to production and published, whichever comes first, before public
disclosure. If we need longer we will ask and explain why. If we are
unresponsive for 14 days at any point, you are free to disclose.

We will credit you in the release notes and in `PUBLISHED_PCR.md` for the
fixed release unless you ask not to be named.

## Safe harbor

We will not pursue legal action against, or report to law enforcement, anyone
who in good faith:

- follows this policy,
- avoids privacy violations, data destruction, and service degradation
  (no denial-of-service testing against production),
- uses their own PayPerQ credit id and only accesses data belonging to it,
- and gives us a reasonable time to fix the issue before disclosing it.

If you are unsure whether something is in bounds, ask first via the channels
above.

## Scope

**In scope**

- Everything in `enclave/`: the TLS termination and certificate handling,
  attestation document generation, EHBP/HPKE unsealing, request routing,
  provider binding, the signed routing receipt, the settle and error paths,
  and what leaves the enclave as metadata.
- `boot.sh`, the `Dockerfile`, and the reproducible-build process
  (`REPRODUCE.md`, `.github/workflows/enclave-build.yml`), including any way
  to make the published PCR0 not correspond to the published source.
- The published trust anchor (`attestation/published-pcr.json`) and the
  rollover / `accepted_pcr0` handling.
- The reference clients in `client/` (`verify.mjs`, `browser-verify.mjs`,
  `nitro-secure-fetch.mjs`).
- The host-side configuration described in `OPERATIONS.md` where it affects
  the trust property (for example the rollback arm).
- Provider key custody inside the enclave (KMS-gated vs. init-channel
  plaintext fallback).

**Especially interested in**

- Any way for the parent instance, PayPerQ's backend, or an AWS operator to
  read request or response content.
- Any way to serve a request to a model or provider other than the one named
  in the signed routing receipt, or to forge a receipt.
- Any way for a client that verified attestation to be downgraded to a
  non-attested path without an error.
- Reproducibility failures: a build from the published commit that does not
  produce the published PCR0.
- Any way to get queries served without being billed for them, or to be
  billed less than the metered cost: bypassing or forging the
  `/enclave/authorize` pre-flight, tampering with the settle (token counts,
  cost, credit id, request id replay), spending from a credit id you do not
  control, or exhausting a balance past zero.
- Any way to make PayPerQ pay a provider without a matching charge to a
  user: amplifying one request into many upstream calls, forcing retries or
  fallbacks that are not settled, abusing the passthrough routes, or
  otherwise running up our provider bills.

**Out of scope for this repository** (report these to the right place instead)

- The ppq.ai web app and the billing backend, both closed source. Report
  those to the same email and we will triage from there.
- The `private/*` (Tinfoil TEE) models' own confidential-VM guarantees; those
  belong to Tinfoil. Our relay to them is in scope.
- AWS Nitro Enclaves itself and upstream model providers (OpenRouter,
  Anthropic, Fireworks, Venice, Google Vertex, AWS Bedrock).
- Denial of service, rate limiting, and resource exhaustion.
- Metadata visibility that the README's threat model already states PayPerQ
  can see (credit id, model, token counts, timing, client IP at the load
  balancer).
- Issues already listed under "Known gaps" in `README.md`, unless you have
  found a way to exploit one that is worse than described.

## Supported versions

Only the enclave image whose PCR0 is listed in
`attestation/published-pcr.json` is supported. During a rollover there are
two entries; both are supported until the outgoing one is pruned. Older
measurements listed in `PUBLISHED_PCR.md` are retired and will not be
patched; a verifying client should refuse them.

## Bounty

We do not run a formal bug bounty program. We do pay, at our discretion and
in bitcoin, for reports that break the privacy or routing guarantee or that
let a user get queries served without paying for them. Tell us in your report
if you would like to be considered.

How we decide, so you know before you send:

- **Paid for impact against the deployed system, not against the source
  alone.** A proof that runs the enclave code against a mocked horse-power
  shows a gap in the measured code; it does not show that a user of ppq.ai or
  api.ppq.ai can reach it. horse-power enforces many of the same rules at
  `/enclave/authorize`, and a guard missing from the enclave but present there
  is a defence-in-depth fix we will make and credit, not a paid finding. If
  you can show the behaviour against production with your own credit id
  (within the safe harbor above), say so; that is what moves a report into
  the paid tier.
- **First report wins.** We pay the first report of an issue and credit later
  independent reports of the same root cause. A different path to the same
  root cause is the same issue. One copy is enough; if you file by both email
  and GitHub, say so.
- **A hostile parent and a hostile horse-power are different things.**
  Content exposure to the parent instance, PayPerQ's backend or an AWS
  operator is at the top of our paid list. Routing substitution by a
  horse-power that lies in its authorize answer (`resolved_model`,
  candidates, free flags) is a known class: horse-power is untrusted for
  routing by design, and the signed receipt is how a client detects it.
  Reports in that class are credited but not paid unless they show content
  exposure or a way around the receipt.
- **Typical payments are in the low hundreds of US dollars**, higher for a
  confirmed content exposure or a repeatable unbilled-query path. We do not
  pay for duplicates, items already under "Known gaps" in `README.md`,
  hardening suggestions, or behaviour that overbills the user rather than
  PayPerQ. We fix and credit those all the same. We are a small company
  paying from revenue, not a funded program.
- **One issue per report, reproduced before sending.** Tool-assisted review
  is welcome and most good reports we receive used it. A report that asserts
  a vulnerability without having run anything, or that describes the design
  as a flaw (the credit id is the credential; see `README.md`), is closed
  without payment.
- **Payment goes to an address you confirm on the original thread** after we
  have confirmed the issue.

## Related

- Threat model and known gaps: `README.md`
- How to verify the running enclave yourself: `VERIFY.md`
- How to reproduce the build: `REPRODUCE.md`
- Local verifier proxy: https://github.com/PayPerQ/ppq-privacy-verifier
