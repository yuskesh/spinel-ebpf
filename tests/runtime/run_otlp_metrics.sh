#!/usr/bin/env bash
#
# run_otlp_metrics.sh -- verifies per-method RED counters turning into OTLP metrics.
#
# Decodes the ExportMetricsServiceRequests that otlp_metrics_method_build produces
# with `protoc --decode` and asserts all three parts: the Sum (counter), the
# ExponentialHistogram (log2 buckets, so scale=0) and the explicit-bucket
# Histogram. One request = one metric; the assertion that earns its keep here is
# that the calls payload contains no latency, because that bundling is what let a
# backend's refusal of one type take the other one down with it.
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
echo "[metrics] building sample OTLP parts -> $TMP"
"$TMP/otlp_metrics" "$TMP"

echo "[metrics] decoding with protoc"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
for k in calls latency_exp latency_hist; do
  "$PROTOC" --decode=opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest \
    -I "$PROTO_ROOT" \
    opentelemetry/proto/collector/metrics/v1/metrics_service.proto \
    < "$TMP/$k.pb" > "$TMP/$k.txt"
done
cp "$TMP/calls.txt" "$TMP/decoded.txt"   # the resource assertions hold for any part

echo "----- decoded (calls) -----"; cat "$TMP/calls.txt"; echo "---------------------------"

echo "[metrics] asserting: one request = one metric"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
# The calls payload carries no latency -- that is what un-bundling means.
otlp_assert "$TMP/calls.txt" 'name: "spnl_method_calls_total"'
otlp_count  "$TMP/calls.txt" '    metrics {' 1
if grep -q 'spnl_method_latency_ns' "$TMP/calls.txt"; then
  echo "  UNEXPECTED: the calls payload has the latency bundled in"; OTLP_FAIL=1
else echo "  ok: no latency in the calls payload"; fi
otlp_assert "$TMP/latency_exp.txt" 'name: "spnl_method_latency_ns"'
otlp_count  "$TMP/latency_exp.txt" '    metrics {' 1
if grep -q 'spnl_method_calls_total' "$TMP/latency_exp.txt"; then
  echo "  UNEXPECTED: the latency payload has the calls bundled in"; OTLP_FAIL=1
else echo "  ok: no calls in the latency payload"; fi

echo "[metrics] asserting Sum data points"
otlp_assert "$TMP/calls.txt" 'as_int: 177'
otlp_assert "$TMP/calls.txt" 'as_int: 500'
otlp_assert "$TMP/calls.txt" 'is_monotonic: true'
otlp_assert "$TMP/calls.txt" 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'

echo "[metrics] asserting ExponentialHistogram (log2 -> scale=0)"
otlp_assert "$TMP/latency_exp.txt" 'exponential_histogram {'
otlp_assert "$TMP/latency_exp.txt" 'unit: "ns"'
otlp_assert "$TMP/latency_exp.txt" 'offset: 9'
otlp_assert "$TMP/latency_exp.txt" 'offset: 10'
otlp_assert "$TMP/latency_exp.txt" 'bucket_counts: 100'
otlp_assert "$TMP/latency_exp.txt" 'bucket_counts: 77'
otlp_assert "$TMP/latency_exp.txt" 'bucket_counts: 500'
otlp_assert "$TMP/latency_exp.txt" 'count: 177'
otlp_assert "$TMP/latency_exp.txt" 'count: 500'
# the approximated sum (sum over s of count_s * 1.5*2^s)
otlp_assert "$TMP/latency_exp.txt" 'sum: 313344'
otlp_assert "$TMP/latency_exp.txt" 'sum: 768000'

echo "[metrics] asserting explicit-bucket Histogram (the log2_ns_31 bounds set)"
otlp_assert "$TMP/latency_hist.txt" 'histogram {'
otlp_assert "$TMP/latency_hist.txt" 'unit: "ns"'
# The boundaries are the upper edges of the log2 slots, 2^(k+1)-1. 1048575 is the
# one a %g in the generator used to round to 1.04858e+06 = 1048580, which moves
# five integers into the neighbouring bucket and quietly falsifies the property
# the whole bounds set rests on.
otlp_assert "$TMP/latency_hist.txt" 'explicit_bounds: 1048575'
otlp_assert "$TMP/latency_hist.txt" 'explicit_bounds: 34359738367'
otlp_count  "$TMP/latency_hist.txt" 'explicit_bounds:' 62   # 31 boundaries x 2 data points
otlp_count  "$TMP/latency_hist.txt" 'bucket_counts:' 64     # 32 buckets x 2 data points
# The same numbers appear -- changing the representation never splits a count.
otlp_assert "$TMP/latency_hist.txt" 'bucket_counts: 100'
otlp_assert "$TMP/latency_hist.txt" 'bucket_counts: 77'
otlp_assert "$TMP/latency_hist.txt" 'bucket_counts: 500'
otlp_assert "$TMP/latency_hist.txt" 'count: 177'
otlp_assert "$TMP/latency_hist.txt" 'count: 500'
# The sum does not move when the representation changes.
otlp_assert "$TMP/latency_hist.txt" 'sum: 313344'
otlp_assert "$TMP/latency_hist.txt" 'sum: 768000'

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
