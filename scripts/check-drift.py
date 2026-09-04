#!/usr/bin/env python3
"""Detect the ways the enclave, its published record, and what clients are told
can silently disagree.

WHY THIS EXISTS
---------------
Over 2026-09-02/03 there were four separate drifts, and every one was found by a
person happening to look:

  * the enclave swapped while the frontend pin stayed stale for 35 minutes;
  * preview/staging pinned fc23c3b9 -- three releases behind -- for days;
  * b0d2d76c was built and attested and then simply never deployed;
  * e9d01f90 sat in accepted_pcr0 for ~11 hours after its rollover ended,
    which is a retired image still being accepted.

Each was cheap to fix and invisible until noticed. Before the build pipeline
started working (#31, #40) drift was permanent and expected; now that rotation
is routine, the gap between "a measurement exists" and "it is deployed and
served" is the thing most likely to go quietly wrong.

Exits non-zero when anything disagrees, so a scheduled run turns red rather
than needing a human to read it.
"""

from __future__ import annotations

import json
import re
import ssl
import socket
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

PUBLISHED = "attestation/published-pcr.json"
PIN_URL = "https://ppq.ai/api/enclave-pin"
ENCLAVE_HOST = "enclave.ppq.ai"
INSTANCE_ID = "i-0609bf23c4b57a48e"

# Everything the Dockerfile COPYs into the image is measured; a change to any of
# it moves PCR0. Kept in step with enclave-build.yml's path filters.
MEASURED = (
    "enclave/src/",
    "enclave/boot.sh",
    "enclave/Dockerfile",
    "enclave/package.json",
    "enclave/package-lock.json",
)

CERT_WARN_DAYS = 21
# The build box fills up: a Docker image plus build cache per rebuild, on a 30GB
# root volume. On 2026-09-03 it hit 100% (42MB free), the build died, and
# because the workflow piped it to `tail` the failure was reported as success --
# production silently stayed a release behind. Free space is therefore a drift
# signal in its own right: below this, the NEXT rebuild is at risk, which also
# means there is no working path to an emergency rollback.
DISK_WARN_PCT = 80

problems: list[str] = []
notes: list[str] = []


def problem(msg: str) -> None:
    problems.append(msg)
    print(f"DRIFT: {msg}")


def ok(msg: str) -> None:
    print(f"ok:    {msg}")


def note(msg: str) -> None:
    notes.append(msg)
    print(f"note:  {msg}")


def run(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, capture_output=True, text=True, check=True, timeout=180
    ).stdout.strip()


def deployed_pcr0() -> str | None:
    """PCR0 of the enclave actually running on the box, via SSM."""
    try:
        cid = run(
            [
                "aws", "ssm", "send-command",
                "--instance-ids", INSTANCE_ID,
                "--document-name", "AWS-RunShellScript",
                "--parameters", 'commands=["nitro-cli describe-enclaves"]',
                "--query", "Command.CommandId", "--output", "text",
            ]
        )
        subprocess.run(
            ["bash", "scripts/ci-ssm-wait.sh", cid, INSTANCE_ID],
            capture_output=True, timeout=300,
        )
        out = run(
            [
                "aws", "ssm", "get-command-invocation",
                "--command-id", cid, "--instance-id", INSTANCE_ID,
                "--query", "StandardOutputContent", "--output", "text",
            ]
        )
        enclaves = json.loads(out)
        if not enclaves:
            problem("no enclave is running on the box at all")
            return None
        e = enclaves[0]
        if e.get("State") != "RUNNING":
            problem(f"enclave state is {e.get('State')}, expected RUNNING")
        # --debug-mode zeroes every PCR, and a pinned client would reject an
        # all-zero measurement. Worth catching explicitly rather than as a
        # confusing mismatch.
        if e.get("Flags") != "NONE":
            problem(f"enclave Flags={e.get('Flags')}, expected NONE (debug zeroes PCRs)")
        return e["Measurements"]["PCR0"].lower()
    except Exception as exc:  # noqa: BLE001 - a check that dies is a drift report we lost
        problem(f"could not read the running enclave: {exc}")
        return None


SERVED_SAMPLES = 8


def served() -> list[dict]:
    """Sample the pin route several times, because instances disagree.

    The route caches per serverless instance, so one request only tells you what
    one warm instance happens to hold. Measured on the 2026-09-03 rollover:
    eight minutes after the publish merged, 11 of 12 consecutive requests were
    still served the previous measurement. Sampling once would have called that
    fine or broken depending purely on which instance answered.
    """
    out: list[dict] = []
    for _ in range(SERVED_SAMPLES):
        try:
            with urllib.request.urlopen(PIN_URL, timeout=30) as r:
                out.append(json.loads(r.read().decode()))
        except Exception as exc:  # noqa: BLE001
            problem(f"could not read {PIN_URL}: {exc}")
            return out
    return out


KMS_KEY_ID = "354fe7d0-1eb1-45bf-a581-3de8fe12d87a"
KMS_ALLOW_SID = "AllowDecryptOnlyFromAttestedEnclave"
KMS_CONDITION_KEY = "kms:RecipientAttestation:PCR0"
# {running, previous}. Wider than the client accept-list on purpose — the extra
# entry is the rollback target (see scripts/kms-pcr0-allow.py).
KMS_MAX_ALLOWED = 2


def kms_allowed_pcr0s() -> list[str] | None:
    """The measurements the provider-key CMK will decrypt for.

    Checked because it rotted for months without anyone noticing: on 2026-09-04
    it still named `4a237681…` and `fc23c3b9…` while production ran `fded2125`.
    Nothing exercised it -- the cutover sends plaintext secrets, so boot.sh
    never takes the KMS branch (#11) -- and nothing checked it, so a decrypt
    would simply have been denied the first time anyone relied on it.
    """
    try:
        raw = run(
            ["aws", "kms", "get-key-policy", "--key-id", KMS_KEY_ID,
             "--policy-name", "default", "--region", "us-east-1",
             "--query", "Policy", "--output", "text"]
        )
        policy = json.loads(raw)
        for s in policy.get("Statement", []):
            if s.get("Sid") != KMS_ALLOW_SID:
                continue
            for _op, kv in s.get("Condition", {}).items():
                if KMS_CONDITION_KEY in kv:
                    v = kv[KMS_CONDITION_KEY]
                    return [v.lower()] if isinstance(v, str) else [x.lower() for x in v]
        problem(f"CMK has no {KMS_ALLOW_SID} / {KMS_CONDITION_KEY} condition")
        return None
    except Exception as exc:  # noqa: BLE001
        note(f"could not read the provider-key CMK policy: {exc}")
        return None


def cert_days_left(host: str) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=20) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                not_after = ss.getpeercert()["notAfter"]
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        return (exp - datetime.now(timezone.utc)).days
    except Exception as exc:  # noqa: BLE001
        problem(f"could not read the {host} certificate: {exc}")
        return None


def main() -> int:
    doc = json.load(open(PUBLISHED))
    current = doc["current"]["pcr0"].lower()
    accepted = [p.lower() for p in doc.get("accepted_pcr0", [])]
    src = doc["current"].get("source_commit")

    print(f"published current : {current}")
    print(f"published accepted: {len(accepted)} entr(y/ies)")
    print()

    # 1. Is what runs what we published?
    running = deployed_pcr0()
    if running:
        if running == current:
            ok("running enclave matches the published current measurement")
        elif running in accepted:
            note(
                "running enclave is accepted but is NOT `current` — mid-rollover, "
                "or a swap whose follow-up publish never landed"
            )
        else:
            problem(
                f"running enclave {running[:16]}… is not even in accepted_pcr0 — "
                "clients that verify attestation are falling back right now"
            )

    # 2. Is what clients are told what we published?
    samples = served()
    if samples:
        pins = {(x.get("pcr0") or "").lower() for x in samples}
        origins = {x.get("origin") for x in samples}

        # Instances that have not refreshed are the normal, transient state just
        # after a publish. Report it as its own condition rather than letting
        # whichever instance answered decide the verdict.
        if len(pins) > 1:
            note(
                f"instances disagree ({len(pins)} distinct pins across "
                f"{len(samples)} samples) — a publish is still propagating"
            )

        if current not in pins:
            problem(
                f"no sampled instance serves the published current "
                f"{current[:16]}… (saw: {', '.join(x[:16] + chr(8230) for x in pins)})"
            )
        elif len(pins) == 1:
            ok("served pin matches the published current measurement")

        # origin is the tell for "GitHub was unreachable and the stale
        # build-time constant is being served instead" — invisible otherwise.
        if origins != {"published"}:
            problem(
                f"origin values {sorted(map(str, origins))} — some instance is NOT "
                "reading the published record (env fallback or a stale copy)"
            )

        # The one that actually matters for users: whatever an instance serves,
        # it must accept the measurement the enclave is really running.
        if running:
            bad = [
                x for x in samples
                if running not in [p.lower() for p in (x.get("accepted") or [])]
            ]
            if bad:
                problem(
                    f"{len(bad)}/{len(samples)} sampled instances do not accept the "
                    "running measurement — clients hitting those fall back"
                )
            else:
                ok("every sampled instance accepts the running measurement")

    # 3. Has measured source moved since the deployed measurement was built?
    #
    # The question is whether MAIN has moved past what is deployed, so the diff
    # ends at main and not at HEAD. Ending at HEAD made the answer depend on
    # whichever branch the check happened to be run from: on a feature branch
    # touching enclave/src/** it reported drift for work that had not landed
    # anywhere, and on a branch behind main it would miss real drift entirely.
    # Neither is the question being asked. CI checks out the pushed commit and
    # has no local `main`, so the fallback chain ends at HEAD.
    if src:
        try:
            tip = next(
                (
                    r
                    for r in ("origin/main", "main")
                    if subprocess.run(
                        ["git", "rev-parse", "--verify", "--quiet", r],
                        capture_output=True,
                    ).returncode
                    == 0
                ),
                "HEAD",
            )
            changed = run(["git", "diff", "--name-only", f"{src}..{tip}"]).splitlines()
            drifted = [f for f in changed if f.startswith(MEASURED)]
            if drifted:
                problem(
                    f"measured source changed on {tip} since {src} without a "
                    "cutover: " + ", ".join(drifted)
                )
            else:
                ok(f"no measured-path changes on {tip} since {src}")
        except Exception as exc:  # noqa: BLE001
            note(f"could not diff measured paths against {src}: {exc}")

    # 4. Accept-list hygiene. An extra entry is only justified across a
    # rollover, and clients converge within the route's cache TTL — so
    # once the running enclave IS `current`, an extra entry means work is
    # outstanding either way.
    #
    # It deliberately does NOT say which. From this file alone a second entry
    # is indistinguishable between "retired, prune it" and "pre-accepted
    # incoming, cut over to it" — both are legitimate states and both need
    # action. Asserting the wrong one trains people to disbelieve the check,
    # which is worse than naming both.
    if len(accepted) > 1 and running == current:
        extra = [p for p in accepted if p != current]
        problem(
            f"{len(extra)} measurement(s) accepted besides the running one: "
            + ", ".join(p[:16] + "…" for p in extra)
            + " — either retired (prune) or pre-accepted (cut over); "
            "an accept-list should not sit wider than a rollover"
        )
    elif len(accepted) > 1:
        note(f"{len(accepted)} accepted measurements — a rollover appears to be in progress")
    else:
        ok("accept-list holds exactly the current measurement")

    # 4a. Does the provider-key CMK still admit what is running?
    #
    # This is the check whose absence let the allow-list name two dead
    # measurements for months. It is deliberately asserted against the RUNNING
    # enclave rather than `current`: the CMK gates a live boot-time decrypt, so
    # the question is whether the thing executing right now can get its keys,
    # not whether the published record agrees with itself.
    if running:
        kms_allowed = kms_allowed_pcr0s()
        if kms_allowed is not None:
            if running not in kms_allowed:
                problem(
                    f"the running measurement {running[:16]}… is NOT in the "
                    "provider-key CMK allow-list — a KMS-gated boot would be "
                    "denied its keys (allowed: "
                    + ", ".join(p[:16] + "…" for p in kms_allowed) + ")"
                )
            elif len(kms_allowed) > KMS_MAX_ALLOWED:
                problem(
                    f"CMK allows {len(kms_allowed)} measurements, expected at most "
                    f"{KMS_MAX_ALLOWED} ({{running, previous}}) — retired "
                    "measurements that can still decrypt are exactly the drift "
                    "this check exists to catch"
                )
            else:
                ok(
                    f"provider-key CMK admits the running measurement "
                    f"({len(kms_allowed)} allowed)"
                )

    # 4b. Can the box still build? A full disk breaks rebuilds silently, and a
    # box that cannot rebuild also cannot roll back.
    try:
        out = run(
            [
                "aws", "ssm", "send-command", "--instance-ids", INSTANCE_ID,
                "--document-name", "AWS-RunShellScript",
                "--parameters", 'commands=["df --output=pcent / | tail -1 | tr -dc 0-9"]',
                "--query", "Command.CommandId", "--output", "text",
            ]
        )
        subprocess.run(["bash", "scripts/ci-ssm-wait.sh", out, INSTANCE_ID],
                       capture_output=True, timeout=300)
        pct = run(
            [
                "aws", "ssm", "get-command-invocation", "--command-id", out,
                "--instance-id", INSTANCE_ID,
                "--query", "StandardOutputContent", "--output", "text",
            ]
        ).strip()
        used = int(pct)
        if used >= DISK_WARN_PCT:
            problem(
                f"build box root filesystem is {used}% full -- rebuilds will fail "
                "silently and there is no path to an emergency rollback "
                "(docker builder prune -af; docker image prune -af)"
            )
        else:
            ok(f"build box disk {used}% used")
    except Exception as exc:  # noqa: BLE001
        note(f"could not read build box disk usage: {exc}")

    # 5. The cert has no renewal timer (README gap 3). Today a missed renewal is
    # a browser warning; once TLS terminates in-enclave (#52) it is a hard
    # outage for API clients with no fallback.
    days = cert_days_left(ENCLAVE_HOST)
    if days is not None:
        if days < CERT_WARN_DAYS:
            problem(f"{ENCLAVE_HOST} certificate expires in {days} days and renewal is manual")
        else:
            ok(f"{ENCLAVE_HOST} certificate has {days} days left")

    print()
    if problems:
        print(f"{len(problems)} drift(s) found")
        return 1
    print("no drift" + (f" ({len(notes)} note(s))" if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
