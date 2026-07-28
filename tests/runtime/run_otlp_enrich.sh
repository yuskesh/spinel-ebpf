#!/usr/bin/env bash
# run_otlp_enrich.sh -- unit test for the userspace enricher registry.
#  Checks registry introspection (k8s->peer ordering, the per-signal mask), the
#  no-op case, the k8s-then-peer attribute order on CONN, and that peer is excluded
#  from DNS (byte-identical output). No libbpf or nanopb dependency: it runs on a
#  host and uses the inode of a fake kubepods hierarchy as the cgid.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
OTLP="$REPO_ROOT/src/runtime/otlp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[enrich] enricher registry unit test (otlp_enrich + otlp_k8s + otlp_peer)"
"$CC" -O2 -Wall -Wextra -I "$OTLP" -I "$REPO_ROOT/include" \
  tests/runtime/otlp_enrich_test.c \
  "$OTLP/otlp_enrich.c" "$OTLP/otlp_k8s.c" "$OTLP/otlp_peer.c" \
  -o "$TMP/enrich"
"$TMP/enrich"
echo "[enrich] OK"
