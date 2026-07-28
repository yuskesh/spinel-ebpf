#!/usr/bin/env bash
#
# run_otlp_json.sh -- verification of the OTLP/HTTP+JSON encoder (otlp_json.c).
# Builds the metrics/traces/logs JSON from sample data and checks validity plus the
# expected fields with python. No nanopb dependency -- the JSON path never touches
# protobuf.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PY="${PYTHON:-python3}"
OTLP="$REPO_ROOT/src/runtime/otlp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[json] compiling otlp_json encoder test"
"$CC" -O2 -Wall -Wextra -Werror -I "$OTLP" \
  tests/runtime/otlp_json_test.c "$OTLP/otlp_json.c" -o "$TMP/jt"

for sig in metrics traces logs; do
  "$TMP/jt" "$sig" > "$TMP/$sig.json"
  if "$PY" -c "import json,sys; json.load(open('$TMP/$sig.json'))" 2>/dev/null; then
    echo "  ok: $sig is valid JSON"
  else
    echo "  INVALID JSON: $sig"; OTLP_FAIL=1
  fi
done

# proto3 JSON mapping: 64-bit values are strings, enums are numbers, trace_id is hex
otlp_assert "$TMP/metrics.json" '"spnl_method_calls_total"'
otlp_assert "$TMP/metrics.json" '"asInt":"500"'
otlp_assert "$TMP/metrics.json" '"aggregationTemporality":2'
otlp_assert "$TMP/metrics.json" '"code.function"'
otlp_assert "$TMP/metrics.json" '"exponentialHistogram"'
otlp_assert "$TMP/metrics.json" '"bucketCounts":["300","200"]'
otlp_assert "$TMP/traces.json" '"traceId":"0102030405060708090a0b0c0d0e0f10"'
otlp_assert "$TMP/traces.json" '"spanId":"a0a1a2a3a4a5a6a7"'
otlp_assert "$TMP/traces.json" '"name":"add"'
otlp_assert "$TMP/logs.json" '"intValue":"42"'
otlp_assert "$TMP/logs.json" '"stringValue":"hello"'
otlp_assert "$TMP/logs.json" '"eventName":"evt"'
otlp_assert "$TMP/logs.json" '"severityText":"INFO"'

otlp_done "OTLP/JSON encoders (metrics/traces/logs, proto3 JSON mapping)"
