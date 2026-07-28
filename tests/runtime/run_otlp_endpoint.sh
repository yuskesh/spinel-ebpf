#!/usr/bin/env bash
#
# run_otlp_endpoint.sh -- path extraction from an OTLP endpoint URL, and the
# default port for each scheme.
#
# A per-signal endpoint (OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT) has to be used
# verbatim, so this checks that otlp_http_endpoint_path preserves the path and that
# https:// defaults to 443. A pure parse test -- no network needed.
#
# Usage: sh tests/runtime/run_otlp_endpoint.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
OTLP="$REPO_ROOT/src/runtime/otlp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$CC" -O2 -Wall -Wextra -Werror -I "$OTLP" \
  tests/runtime/otlp_endpoint_test.c "$OTLP/otlp_http.c" \
  -lz -o "$TMP/endpoint_test"

"$TMP/endpoint_test"
