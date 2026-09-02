#!/usr/bin/env bash
# Wait for an SSM command to reach a terminal state.
#
# WHY THIS EXISTS
# ---------------
# `aws ssm wait command-executed` has a fixed built-in waiter: 20 attempts at 5
# second intervals, so it gives up after **100 seconds**. An enclave build takes
# minutes. The waiter therefore returned while the command was perfectly healthy
# and still `InProgress`, the caller's status check saw `InProgress` rather than
# `Success`, and the step failed a build that went on to finish normally.
#
# Observed on run 33629781388, the first run that ever got past the credentials
# step: Actions reported "Build the enclave image / failure" while
# `scripts/build-enclave.sh` was still running on the box twelve minutes later.
#
# `--timeout-seconds` on `send-command` does NOT help — it bounds how long SSM
# lets the COMMAND run, not how long the waiter waits for it.
#
# EXIT CODE
# ---------
# Always 0, whatever the command did. This is a wait, not an assertion: every
# call site already reads `Status` itself and decides what to do (some `test`
# for Success, one retries up to three times, one prints the output first).
# Keeping the split means this is also safe inside a retry loop under `set -e`,
# which is exactly where the swap step calls it.
#
# usage: ci-ssm-wait.sh <command-id> <instance-id> [max-seconds]
set -uo pipefail

CMD_ID="${1:?command id required}"
INSTANCE_ID="${2:?instance id required}"
# Default comfortably above the longest --timeout-seconds any caller passes
# (2400, the enclave build). A caller whose command is bounded lower can pass a
# smaller value; there is no benefit to waiting past the command's own timeout.
MAX_SECONDS="${3:-2700}"
INTERVAL=15

status=Pending
deadline=$((SECONDS + MAX_SECONDS))

while [ "$SECONDS" -lt "$deadline" ]; do
  # A freshly sent command can 404 for a moment (InvocationDoesNotExist) before
  # SSM registers the invocation. That is indistinguishable from Pending here
  # and must not end the wait.
  status=$(aws ssm get-command-invocation \
    --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
    --query Status --output text 2>/dev/null || echo Pending)

  case "$status" in
    Success | Failed | TimedOut | Cancelled)
      echo "ssm $CMD_ID -> $status"
      exit 0
      ;;
  esac

  sleep "$INTERVAL"
done

echo "ssm $CMD_ID -> still ${status} after ${MAX_SECONDS}s; stopped waiting" >&2
exit 0
