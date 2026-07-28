#!/usr/bin/env bash
#
# run_otlp_metrics.sh -- verifies per-method RED counters turning into OTLP metrics.
#
# Decodes the ExportMetricsServiceRequest that otlp_metrics_build produces with
# `protoc --decode` and asserts that the Sum (counter) and the ExponentialHistogram
# (log2 buckets, so scale=0) were assembled correctly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PROTO_ROOT="$REPO_ROOT/third_party/opentelemetry-proto"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[metrics] compiling metrics encoder test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_metrics_test.c \
  "$OTLP/otlp_metrics.c" "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" "$OTLP/otlp_json.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -lz \
  -o "$TMP/otlp_metrics"

echo "[metrics] building sample OTLP -> $TMP/out.pb"
"$TMP/otlp_metrics" "$TMP/out.pb"

echo "[metrics] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/metrics/v1/metrics_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

echo "[metrics] asserting Sum + ExponentialHistogram mapping"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
# metric names
assert 'name: "spnl_method_calls_total"'
assert 'name: "spnl_method_latency_ns"'
assert 'unit: "ns"'
# Sum (counter) data points
assert 'as_int: 177'
assert 'as_int: 500'
assert 'is_monotonic: true'
assert 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'
# ExponentialHistogram (log2 -> scale=0)
assert 'offset: 9'
assert 'offset: 10'
assert 'bucket_counts: 100'
assert 'bucket_counts: 77'
assert 'bucket_counts: 500'
assert 'count: 177'
assert 'count: 500'
# the approximated sum (sum over s of count_s * 1.5*2^s)
assert 'sum: 313344'
assert 'sum: 768000'
# resource and code.* attributes
assert 'string_value: "spinel-app"'
assert 'key: "code.function"'
assert 'string_value: "fib"'
assert 'string_value: "add"'
assert 'key: "code.lineno"'
assert 'int_value: 19'

otlp_done "per-method RED -> OTLP Sum + ExponentialHistogram"
