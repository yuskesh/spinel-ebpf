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
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/deps/opentelemetry-proto}"
. "$REPO_ROOT/tests/runtime/proto_guard.sh"
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

# The operator's own labels. The values are checked against the wire below.
export OTEL_RESOURCE_ATTRIBUTES="deployment.environment=staging, spnl.tagged = yes ,broken-pair,=novalue"
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

# OTEL_RESOURCE_ATTRIBUTES is OTel's standard way to label this producer. It used to
# be unsupported here (only OTEL_SERVICE_NAME was), which was the gap that Tetragon
# covers with its `tags`; opening the standard door rather than inventing a private
# vocabulary is what this pins. The protobuf resource encoder
# (otlp_enc_resource_attrs) is exercised by THIS test, which is why the check lives
# here -- run_otlp_send.sh hand-builds its payload and never reaches the resource
# encoder, and run_otlp_extras.sh is SKIPPED WHOLE when grpcio is missing (both
# measured, so neither would be a check that quietly stops running).
# Two malformed pairs are mixed in on purpose: one with no '=' and one with an
# empty key.
assert 'key: "deployment.environment"'
assert 'string_value: "staging"'
assert 'key: "spnl.tagged"'
assert 'string_value: "yes"'          # surrounding whitespace is trimmed
assert 'key: "telemetry.sdk.name"'    # our own identity survives (labels are appended)
if grep -q "broken-pair" "$TMP/decoded.txt"; then
  echo "  UNEXPECTED: a pair with no '=' became an attribute"; OTLP_FAIL=1
else echo "  ok: the pair with no '=' was dropped"; fi
if grep -q "novalue" "$TMP/decoded.txt"; then
  echo "  UNEXPECTED: an empty key became an attribute"; OTLP_FAIL=1
else echo "  ok: the empty key was dropped"; fi

otlp_done "per-method RED -> OTLP Sum + ExponentialHistogram"
