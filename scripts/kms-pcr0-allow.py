#!/usr/bin/env python3
"""Keep the CMK's attestation allow-list in step with enclave rotations.

WHY THIS EXISTS
---------------
The CMK that gates the provider keys allows `kms:Decrypt` -- and, since #83,
`kms:GenerateDataKey` -- only when `kms:RecipientAttestation:PCR0` matches a
listed measurement. Both actions live on the SAME statement deliberately: this
script edits only that statement's condition, so an action added beside them
rides along with no change here. Splitting them across two statements would
mean this script silently maintained the allow-list for one and not the other. Nothing kept that
list current, so on 2026-09-04 it still named `4a237681…` and `fc23c3b9…` --
both long retired, `fc23c3b9` being the very measurement the drift check was
written about. Production was running `fded2125`. A decrypt attempted that day
would have been denied.

It rotted invisibly for one reason: no code path exercised it. The cutover sends
plaintext secrets, so `boot.sh` never takes the KMS branch, so nothing ever
failed. A PCR0-bound resource that nothing exercises and nothing checks will
always drift -- the client accept-list survives only because every rotation
touches it AND the drift check goes red when it is wrong. This script is the
first half of giving the CMK the same treatment; `check-drift.py` is the second.

ORDERING, WHICH IS THE WHOLE POINT
----------------------------------
Same shape as `accepted_pcr0`: GRANT the incoming measurement before the swap,
PRUNE after the new image is confirmed running. Doing it the other way leaves a
window where the thing that is running cannot decrypt.

Pruning deliberately keeps the outgoing measurement as well, so the list holds
{running, previous}. That preserves a one-step rollback: an emergency swap back
to the previous image must still be able to decrypt, and there is no rebuild
short of ~25 minutes. That is one entry wider than the client accept-list, and
the reason is worth stating -- for clients an extra entry means a retired image
is still trusted, while here it means a rollback target still works.

SAFETY
------
The policy is READ, one statement's condition is edited, and it is written back.
The document is never rebuilt from scratch: `ProvisionerAdmin` (the only path
that can repair a bad policy) and `DenyDecryptWithoutAttestation` (the explicit
Deny that closes the non-enclave path) must survive verbatim, and are asserted
before any write.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

KEY_ID = "354fe7d0-1eb1-45bf-a581-3de8fe12d87a"
REGION = "us-east-1"
ALLOW_SID = "AllowDecryptOnlyFromAttestedEnclave"
CONDITION_KEY = "kms:RecipientAttestation:PCR0"
# Statements that must exist untouched after any edit. Losing ProvisionerAdmin
# means nobody can fix the policy again; losing the Deny silently reopens
# decrypt to a non-enclave caller.
REQUIRED_SIDS = ("ProvisionerAdmin", "DenyDecryptWithoutAttestation")

PCR0_RE_LEN = 96

# KMS GetKeyPolicy is eventually consistent — a policy written seconds ago may
# not be visible yet. Bounded, because an entry that never appears is a real
# error and must not be waited on forever.
CONSISTENCY_ATTEMPTS = 6
CONSISTENCY_SLEEP_S = 5


def run(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, capture_output=True, text=True, check=True, timeout=120
    ).stdout


def valid_pcr0(v: str) -> str:
    v = v.strip().lower()
    if len(v) != PCR0_RE_LEN or any(c not in "0123456789abcdef" for c in v):
        raise argparse.ArgumentTypeError(f"not a PCR0 (96 hex chars): {v[:24]}…")
    return v


def get_policy() -> dict:
    out = run(
        ["aws", "kms", "get-key-policy", "--key-id", KEY_ID,
         "--policy-name", "default", "--region", REGION,
         "--query", "Policy", "--output", "text"]
    )
    return json.loads(out)


def allow_statement(policy: dict) -> dict:
    for s in policy.get("Statement", []):
        if s.get("Sid") == ALLOW_SID:
            return s
    raise SystemExit(f"FATAL: no statement with Sid={ALLOW_SID}; refusing to guess")


def current_list(policy: dict) -> list[str]:
    cond = allow_statement(policy).get("Condition", {})
    for op, kv in cond.items():
        if CONDITION_KEY in kv:
            v = kv[CONDITION_KEY]
            return [v.lower()] if isinstance(v, str) else [x.lower() for x in v]
    return []


def set_list(policy: dict, values: list[str]) -> None:
    st = allow_statement(policy)
    cond = st.get("Condition", {})
    for op, kv in cond.items():
        if CONDITION_KEY in kv:
            # Preserve the operator already in use (StringEqualsIgnoreCase);
            # changing it would quietly change matching semantics.
            kv[CONDITION_KEY] = values
            return
    raise SystemExit(f"FATAL: {ALLOW_SID} has no {CONDITION_KEY} condition; refusing to add one")


def put_policy(policy: dict) -> None:
    sids = {s.get("Sid") for s in policy.get("Statement", [])}
    for required in REQUIRED_SIDS:
        if required not in sids:
            raise SystemExit(f"FATAL: {required} missing from the policy being written; aborting")
    run(
        ["aws", "kms", "put-key-policy", "--key-id", KEY_ID,
         "--policy-name", "default", "--region", REGION,
         "--policy", json.dumps(policy)]
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--show", action="store_true", help="print the current allow-list")
    g.add_argument("--grant", type=valid_pcr0, metavar="PCR0",
                   help="add a measurement (idempotent). Run BEFORE the swap.")
    g.add_argument("--prune-to", type=valid_pcr0, nargs="+", metavar="PCR0",
                   help="set the list to exactly these. Run AFTER the swap is verified.")
    g.add_argument("--prune-keeping-previous", type=valid_pcr0, metavar="RUNNING",
                   help="keep RUNNING plus the most recent OTHER allowed measurement. "
                        "Use after a swap: unlike --prune-to it cannot collapse to a "
                        "single entry when the incoming measurement equals the outgoing "
                        "one (a same-measurement restart), which would silently drop the "
                        "rollback target's ability to decrypt.")
    ap.add_argument("--dry-run", action="store_true", help="show the change, write nothing")
    args = ap.parse_args()

    policy = get_policy()
    before = current_list(policy)
    print("current allow-list:")
    for p in before:
        print(f"  {p}")
    if args.show:
        return 0

    if args.grant:
        after = before if args.grant in before else [args.grant] + before
    elif args.prune_keeping_previous:
        # Keep the running measurement plus the most recent OTHER one.
        #
        # `--prune-to running previous` looks equivalent and is not: on a
        # same-measurement restart (redelivering an init blob without changing
        # the image) the caller's "previous" IS the running measurement, the
        # pair dedupes to one entry, and the actual rollback target silently
        # loses its ability to decrypt. That happened on 2026-09-04 during the
        # #11 step-2 restart and had to be repaired by hand.
        running = args.prune_keeping_previous
        if running not in before:
            raise SystemExit(
                f"FATAL: {running[:16]}… is not currently allowed; grant it first."
            )
        others = [p for p in before if p != running]
        after = [running] + others[:1]
    else:
        after = list(dict.fromkeys(args.prune_to))
        missing = [p for p in after if p not in before]
        # GetKeyPolicy is EVENTUALLY CONSISTENT. On 2026-09-04 the cutover's
        # grant step wrote and read back successfully, and the prune step ~60s
        # later still saw the pre-grant policy -- so this guard fired on a
        # measurement that had in fact been granted, and the prune was skipped,
        # leaving a retired measurement able to decrypt. (Second time today a
        # stale read from an eventually-consistent API produced a wrong
        # decision; the first was GitHub's issue search index.)
        #
        # So a missing entry is re-read before it is believed. The guard itself
        # stays -- pruning to something never granted would be a grant wearing
        # the wrong name, skipping the before-the-swap ordering this exists to
        # enforce -- it just stops trusting one sample.
        for attempt in range(1, CONSISTENCY_ATTEMPTS + 1) if missing else []:
            print(
                f"\n{len(missing)} requested measurement(s) not in the policy yet; "
                f"KMS reads are eventually consistent — re-reading "
                f"({attempt}/{CONSISTENCY_ATTEMPTS})"
            )
            time.sleep(CONSISTENCY_SLEEP_S)
            policy = get_policy()
            before = current_list(policy)
            missing = [p for p in after if p not in before]
            if not missing:
                print("appeared on re-read; continuing")
                break
        if missing:
            raise SystemExit(
                "FATAL: --prune-to names measurements that are not currently allowed: "
                + ", ".join(m[:16] + "…" for m in missing)
                + f"\n(still absent after {CONSISTENCY_ATTEMPTS} re-reads, so this is"
                " not consistency lag.)\nGrant first, then prune."
            )

    if after == before:
        print("\nno change needed")
        return 0

    print("\nnew allow-list:")
    for p in after:
        print(f"  {p}" + ("  (added)" if p not in before else ""))
    for p in before:
        if p not in after:
            print(f"  -- removing {p}")

    if args.dry_run:
        print("\ndry run — nothing written")
        return 0

    set_list(policy, after)
    put_policy(policy)

    # Read back rather than trusting the write: this policy is the only thing
    # standing between a host-compromise and the provider keys.
    verify = current_list(get_policy())
    if sorted(verify) != sorted(after):
        raise SystemExit(f"FATAL: read-back mismatch. Policy now holds: {verify}")
    print("\nwritten and verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
