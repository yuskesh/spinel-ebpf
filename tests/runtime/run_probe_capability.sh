#!/usr/bin/env bash
#
# run_probe_capability.sh -- the capability table, on the host.
#
# The firmware is the authority on what it can observe, so it publishes a table
# and the installer reads it. Both halves are freestanding C over a plain buffer,
# which means the whole negotiation — publish, read, admit, and every way it can
# be refused — is testable with no board and no firmware. That is the point of
# doing U3 before the dispatcher: the format gets settled by a test rather than
# by whatever the first proof-of-concept needed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-cc}"
AMP="$REPO_ROOT/src/runtime/amp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[u3] building the capability test"
"$CC" -O2 -Wall -Wextra -Werror -std=c11 \
  -I "$REPO_ROOT/include" -I "$AMP" \
  tests/runtime/probe_capability_test.c "$AMP/probe_capability.c" \
  -o "$TMP/probe_cap"

"$TMP/probe_cap"
