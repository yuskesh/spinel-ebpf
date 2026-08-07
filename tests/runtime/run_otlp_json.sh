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

# OTEL_RESOURCE_ATTRIBUTES has to come out the SAME on the protobuf path and on the
# JSON path -- that is what jw_resource declares of itself ("matches the protobuf
# otlp_enc_resource_attrs"). Dropping the operator's labels on the JSON path only is
# exactly the sort of thing that can happen here, so both are pinned.
export OTEL_RESOURCE_ATTRIBUTES="deployment.environment=staging, spnl.tagged = yes ,broken-pair,=novalue"

echo "[json] compiling otlp_json encoder test"
"$CC" -O2 -Wall -Wextra -Werror -I "$OTLP" \
  tests/runtime/otlp_json_test.c "$OTLP/otlp_json.c" -o "$TMP/jt"

for sig in metrics metrics_lat metrics_lat_hist traces logs; do
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
# One metric per request: the calls payload carries no latency.
if grep -q 'spnl_method_latency_ns' "$TMP/metrics.json"; then
  echo "  UNEXPECTED: the calls JSON has the latency bundled in"; OTLP_FAIL=1
else echo "  ok: no latency in the calls JSON"; fi
otlp_assert "$TMP/metrics_lat.json" '"exponentialHistogram"'
otlp_assert "$TMP/metrics_lat.json" '"bucketCounts":["300","200"]'
# Explicit buckets (the log2_ns_31 bounds set): slots 10 and 11 land in buckets
# 10 and 11 with the same counts.
otlp_assert "$TMP/metrics_lat_hist.json" '"histogram"'
otlp_assert "$TMP/metrics_lat_hist.json" '"explicitBounds"'
otlp_assert "$TMP/metrics_lat_hist.json" '"0","0","0","0","0","0","0","0","0","0","300","200"'
otlp_assert "$TMP/traces.json" '"traceId":"0102030405060708090a0b0c0d0e0f10"'
otlp_assert "$TMP/traces.json" '"spanId":"a0a1a2a3a4a5a6a7"'
otlp_assert "$TMP/traces.json" '"name":"add"'
otlp_assert "$TMP/logs.json" '"intValue":"42"'
otlp_assert "$TMP/logs.json" '"stringValue":"hello"'
otlp_assert "$TMP/logs.json" '"eventName":"evt"'
otlp_assert "$TMP/logs.json" '"severityText":"INFO"'

# The resource attributes ride all three signals (the same treatment the protobuf
# path gives them), whitespace is trimmed, and malformed pairs are dropped.
for sig in metrics traces logs; do
  otlp_assert "$TMP/$sig.json" '"deployment.environment"'
  otlp_assert "$TMP/$sig.json" '"stringValue":"staging"'
  otlp_assert "$TMP/$sig.json" '"spnl.tagged"'
  otlp_assert "$TMP/$sig.json" '"telemetry.sdk.name"'   # our own identity survives
  if grep -q "broken-pair" "$TMP/$sig.json"; then
    echo "  UNEXPECTED($sig): a pair with no '=' became an attribute"; OTLP_FAIL=1
  fi
  if grep -q "novalue" "$TMP/$sig.json"; then
    echo "  UNEXPECTED($sig): an empty key became an attribute"; OTLP_FAIL=1
  fi
done

otlp_done "OTLP/JSON encoders (metrics/traces/logs, proto3 JSON mapping)"
