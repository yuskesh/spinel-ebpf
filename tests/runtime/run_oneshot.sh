#!/usr/bin/env bash
#
# run_oneshot.sh -- event-boxed one-shot counter (SPNL_MAX_EVENTS) unit test.
#
# Verifies spnl_oneshot_add threshold semantics: unset/0 = unlimited (legacy),
# K>0 flips the "reached" signal exactly at the K-th event (single adds) and at
# the batch that crosses K (batch adds, honest overshoot). The K limit is cached
# per-process, so each scenario runs the test binary once with a different env.
#
# Links spnl_runtime.c (where the counter lives) + libbpf, so this is a
# container test (like the other libbpf-linked tests/runtime tests).
#
# Usage: sh tests/runtime/run_oneshot.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$CC" -O2 -Wall -Wextra -I include -I src/runtime \
  tests/runtime/oneshot_test.c src/runtime/spnl_runtime.c \
  -lbpf -lelf -lz -o "$TMP/oneshot_test"

rc=0
echo "== unlimited (SPNL_MAX_EVENTS unset) =="
( unset SPNL_MAX_EVENTS; "$TMP/oneshot_test" unlimited ) || rc=1
echo "== zero (SPNL_MAX_EVENTS=0) =="
SPNL_MAX_EVENTS=0 "$TMP/oneshot_test" zero || rc=1
echo "== single (SPNL_MAX_EVENTS=100) =="
SPNL_MAX_EVENTS=100 "$TMP/oneshot_test" single || rc=1
echo "== batch (SPNL_MAX_EVENTS=100) =="
SPNL_MAX_EVENTS=100 "$TMP/oneshot_test" batch || rc=1

if [ "$rc" -ne 0 ]; then echo "FAIL: oneshot"; exit 1; fi
echo "PASS: oneshot"
