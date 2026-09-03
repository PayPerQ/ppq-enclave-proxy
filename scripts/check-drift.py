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


def served() -> dict | None:
    try:
        with urllib.request.urlopen(PIN_URL, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        problem(f"could not read {PIN_URL}: {exc}")
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
    s = served()
    if s:
        if (s.get("pcr0") or "").lower() != current:
            problem(
                f"{PIN_URL} serves {(s.get('pcr0') or '')[:16]}… but the published "
                f"current is {current[:16]}…"
            )
        else:
            ok("served pin matches the published current measurement")
        # origin is the tell for "GitHub was unreachable and the stale
        # build-time constant is being served instead" — invisible otherwise.
        if s.get("origin") != "published":
            problem(
                f"origin={s.get('origin')!r}, so the route is NOT reading the "
                "published record (env fallback or a stale copy)"
            )
        if running and running not in [p.lower() for p in (s.get("accepted") or [])]:
            problem("the running measurement is absent from the served accepted list")

    # 3. Has measured source moved since the deployed measurement was built?
    if src:
        try:
            changed = run(["git", "diff", "--name-only", f"{src}..HEAD"]).splitlines()
            drifted = [f for f in changed if f.startswith(MEASURED)]
            if drifted:
                problem(
                    f"measured source changed since {src} without a cutover: "
                    + ", ".join(drifted)
                )
            else:
                ok(f"no measured-path changes since {src}")
        except Exception as exc:  # noqa: BLE001
            note(f"could not diff measured paths against {src}: {exc}")

    # 4. Accept-list hygiene. An extra entry is only justified across a
    # rollover, and clients converge within the route's 5-minute cache — so
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
