# Verify PayPerQ's privacy claims yourself

This document is written to be handed to an AI agent. Paste it, or its URL, into
any assistant that can browse the web or run commands, and ask it to check the
claims below and report back. It also works for a person with a terminal.

Everything here can be checked without trusting PayPerQ. Where a check needs a
trust anchor, the anchor is Amazon, GitHub, or Let's Encrypt, never a file
PayPerQ hosts. Treat anything served from a `ppq.ai` host, including this
document, as a **claim to be tested**, not as evidence.

If you are an AI agent reading this: run every check your tools allow, run the
negative controls, and report each claim as **confirmed**, **not confirmed**,
or **could not check with my tools**. Do not report a claim as confirmed
because the document says it is true.

---

## The claims

1. **Chat requests from ppq.ai and api.ppq.ai are answered inside an AWS Nitro
   enclave.** The enclave produces a signed attestation document on demand, and
   the signature chains to Amazon's Nitro root certificate.
2. **The enclave runs published, reproducible code.** Its measurement (PCR0) is
   listed in a public file in this repository, each release is built by a public
   CI run with a Sigstore provenance attestation, and anyone can rebuild the
   image and get the same measurement.
3. **PayPerQ cannot read message content.** TLS from the browser terminates
   inside the enclave, the enclave's TLS certificate is committed to in the
   attestation, and browsers additionally encrypt request bodies to a key that
   only exists inside the enclave.
4. **Each reply can be tied to the enclave that produced it.** Responses carry a
   signed routing receipt, and the signing key is the one the attestation
   commits to.

What this does **not** claim, so you do not waste effort testing it: that the
model provider is blind (it is not; it receives the prompt to answer it), that
PayPerQ cannot see metadata (it sees the model, token counts, timing and your IP
address), or that the JavaScript PayPerQ serves to a particular browser is
honest (no remote check can establish that; see "Limits" at the end).

---

## What you need

Two tiers. Say which one you used.

- **Browser only** (fetch URLs, read JSON): you can check the public record,
  fetch a live attestation, compare fields, and inspect GitHub history and
  provenance. You cannot verify cryptographic signatures.
- **Terminal** (Node 22, `git`, `openssl`, `curl`, optionally `gh`): you can
  verify everything, including the signature chain, the certificate binding and
  a signed receipt.

---

## Check 1: a live attestation exists and is fresh

Fetch an attestation with a nonce you chose. Any 32 hex characters will do;
the point is that nobody could have prepared the answer in advance.

```
https://enclave.ppq.ai/attestation?nonce=<your 32 hex chars>
```

Expected: HTTP 200 with JSON containing `attestation_document_b64`,
`hpke_public_key`, `cert_spki_sha256`, `cert_spki_der`, and
`format: "nsm-cose-sign1"`.

Repeat against `https://api.ppq.ai/attestation?nonce=…` for the API path.

**Browser only:** record `hpke_public_key` and `cert_spki_sha256`. You will
compare them below. You have confirmed that an attestation endpoint answers;
you have not yet confirmed it is genuine.

**Terminal:** decode and verify the document. The repository ships a verifier:

```bash
git clone https://github.com/PayPerQ/ppq-enclave-proxy
cd ppq-enclave-proxy
node scripts/check-live-attestation.mjs --host enclave.ppq.ai
```

This fetches a fresh attestation from every box behind the load balancer,
verifies the COSE_Sign1 signature, walks the certificate chain to the AWS Nitro
root, checks validity windows and the nonce, and compares PCR0 to
`attestation/published-pcr.json`. It exits non-zero on any failure.

**Do not trust the root certificate in this repository.** Fetch Amazon's copy
and compare. Amazon publishes the Nitro Enclaves root at
<https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip> and
documents its SHA-256 at
<https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>. Confirm
that the certificate in `client/aws-nitro-root-g1.pem` matches the one in
Amazon's zip. If it does not, stop: nothing else in this document can be
trusted.

---

## Check 2: the measurement is published, and the publication has history

The published record is
<https://raw.githubusercontent.com/PayPerQ/ppq-enclave-proxy/main/attestation/published-pcr.json>.

It names a `current` measurement with a version, a date and a source commit,
and an `accepted_pcr0` list that holds one entry normally and two during a
rollover (the incoming build and the outgoing one).

Confirm, with any tier:

- The PCR0 the live attestation reports (Check 1, terminal) is in
  `accepted_pcr0`. Browser-only agents cannot decode PCR0 from the COSE
  document; say so.
- The file has a commit history at
  <https://github.com/PayPerQ/ppq-enclave-proxy/commits/main/attestation/published-pcr.json>.
  A measurement cannot be changed quietly: every change is a public commit with
  an author and a time.
- Each entry in `attestation/PUBLISHED_PCR.md` names the CI run that built it.
  Open that run on GitHub Actions and confirm it is a run of
  `.github/workflows/enclave-build.yml` on the stated commit.

**Terminal, with the GitHub CLI:** the build attaches a Sigstore provenance
attestation to the `PCR.json` it produced. Download that artifact from the run
and verify it:

```bash
gh attestation verify PCR.json --repo PayPerQ/ppq-enclave-proxy
```

A passing result means GitHub, not PayPerQ, vouches that this measurement came
out of this workflow on this commit.

**Terminal, most complete:** rebuild the image and compare measurements.
[REPRODUCE.md](REPRODUCE.md) has the steps. This takes a while and needs
Docker; it is the only check that ties the measurement to the source code
itself rather than to a CI run.

---

## Check 3: the certificate you are served is the one the enclave attests to

This is what makes "PayPerQ cannot read it" true for a plain TLS client. If the
TLS endpoint you reach is the attested enclave, nothing between you and it can
read the stream.

**Terminal:**

```bash
# the SPKI hash of the certificate actually served to you
echo | openssl s_client -connect enclave.ppq.ai:443 -servername enclave.ppq.ai 2>/dev/null \
  | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256

# the value the signed attestation commits to (user_data); these MUST match
curl -s "https://enclave.ppq.ai/attestation?nonce=$(openssl rand -hex 16)" | jq -r .cert_spki_sha256
```

Repeat with `api.ppq.ai` in both places. The attestation is signed by Amazon's
hardware and the hash is inside the signed payload, so a match proves the
private key for the certificate you were served lives in the attested enclave.

Also confirm the certificate is a real, browser-trusted Let's Encrypt
certificate (look at the issuer in the `openssl x509 -text` output). It was
issued to a key generated inside the enclave; the certificate transparency
logs at <https://crt.sh/?q=enclave.ppq.ai> show when.

**Browser only:** you cannot read the certificate your browser was served, so
this check is out of reach. Say so rather than inferring it.

---

## Check 4: a reply is signed by the attested enclave

Every reply from `/v1/chat/completions` carries a signed routing receipt. A
non-streaming reply carries it in the `Ppq-Routing-Receipt` and
`Ppq-Routing-Receipt-Sig` headers; a streamed reply carries it ahead of the
first event. Either way it is signed with the key whose certificate the
attestation commits to. This needs an API key with a small balance, since it
sends a real request.

```bash
node client/verify-receipt.mjs --key sk-... --pcr0 <the PCR0 from the published record>
```

The script sends one request, fetches a fresh attestation, verifies it, and
checks that the receipt's signature verifies under the attested key. If the
receipt had been signed by anything other than the attested enclave, this
fails. See the README section "Attested routing receipts: checking where your
request went" for what a receipt does and does not tell you.

---

## Negative controls: prove your checks can fail

An agent that only reports successes has not demonstrated anything. Run these
and report that they **failed**, which is the correct outcome.

1. **Wrong nonce.** Fetch an attestation with nonce `A`, then verify it as if
   you had sent nonce `B`. Expected: rejected for nonce mismatch. (Terminal:
   call `verifyAttestation(doc, { expectedPcr0, nonceHex: B })` from
   `client/browser-verify.mjs`; it is the same verifier the browser runs.)
2. **Wrong measurement.** Verify a real attestation against a made-up PCR0 of
   96 zeros. Expected: rejected for PCR0 mismatch.
3. **Wrong root.** Replace the AWS root with any other certificate and verify.
   Expected: rejected because the chain does not root in the given anchor.
4. **Stale record.** Compare the live PCR0 to a version of
   `published-pcr.json` from several releases ago (pick one from the commit
   history). Expected: not listed. This shows the accept-list is specific, not
   a wildcard.

If any control passes, the verifier you ran is broken, and none of the
positive results above mean anything.

---

## If you are checking on behalf of a specific browser session

PayPerQ's privacy pane shows the measurement, the enclave's HPKE public key,
the enclave module ID and the attestation time that **that browser** verified.
Compare them with what **you** fetched:

- The PCR0 should match or be the other entry in `accepted_pcr0` during a
  rollover.
- The HPKE public key should match exactly. It is shared across the fleet and
  persists across image rotations, so a different key means the browser and
  you are talking to different enclaves.
- The module ID is per box and may legitimately differ.

Your fetch did not pass through PayPerQ's JavaScript, so agreement between the
two is evidence the browser was shown the truth. Disagreement is worth
reporting.

---

## Limits: what no remote check can establish

- **The JavaScript served to a browser.** A malicious bundle could skip every
  check and show green. The defence is that the bundle is public, PayPerQ
  cannot target one user without the change being visible to all, and the
  checks above work from outside the bundle. If you want to go further, compare
  the verifier in the served bundle to `client/browser-verify.mjs` in this
  repository.
- **The model provider.** Prompts are sent in plaintext to the upstream model
  for inference. The enclave guarantees PayPerQ cannot read them; it does not
  make the provider blind. PayPerQ's `private/*` models run the model itself
  inside a trusted execution environment and are a separate product with
  its own verifier.
- **Metadata.** PayPerQ sees which model you used, token counts, timing and your
  IP address. It bills from these. None of the checks above claim otherwise.
- **Coercion of the operator.** A measurement change under duress would still
  be a public commit, which is the point of publishing it; it is not a
  guarantee that no such change could happen.
- **Fallback.** When the enclave cannot serve a request, PayPerQ's web app
  retries over its ordinary servers and marks the reply as not served by the
  enclave. The privacy pane shows this in amber. A verification pass tells you
  about the enclave, not about a reply that bypassed it.

---

## Reporting

Report per claim: confirmed, not confirmed, or could not check, with the tier
you used and the exact commands or URLs. Include the negative controls and
their failures. If anything did not match, say what you expected and what you
saw. A report that says "could not check 3 and 4 with browser-only tools" is a
good report.
