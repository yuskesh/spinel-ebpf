#!/usr/bin/env bash
#
# run_record_mirror.sh -- the generated ringbuf record mirrors read the same
# bytes the hand-written ones did.
#
# record_mirror_test.c builds each channel's byte image using the offsets exactly
# as the runtime used to spell them out by hand, then unpacks with the generated
# spnl_rec_<id>_unpack() and asserts every field -- including the append-only
# reading rule (an older, shorter record that predates the trailing fields is
# still accepted, and the appended fields read back as zero). Host-only: no
# libbpf, no kernel, runs on macOS and in a container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[record-mirror] compiling test"
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$REPO_ROOT/include" -I "$REPO_ROOT/src/runtime/otlp" \
  tests/runtime/record_mirror_test.c -o "$TMP/record_mirror_test"

echo "[record-mirror] running"
"$TMP/record_mirror_test"
