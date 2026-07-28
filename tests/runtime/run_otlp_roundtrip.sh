#!/usr/bin/env bash
#
# run_otlp_roundtrip.sh -- round-trip verification of the protobuf encoding.
#
# Feeds the OTLP bytes nanopb produced to `protoc --decode` and asserts the expected
# fields come back. A broken encoder shows up either as a failed decode or as a
# missing field.
#
# Usage: sh tests/runtime/run_otlp_roundtrip.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
PROTO_ROOT="$REPO_ROOT/third_party/opentelemetry-proto"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[roundtrip] compiling round-trip test (nanopb: pb_encode.c + pb_common.c)"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" \
  tests/runtime/otlp_roundtrip_test.c \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -o "$TMP/otlp_roundtrip"

echo "[roundtrip] running encoder -> $TMP/out.pb"
"$TMP/otlp_roundtrip" "$TMP/out.pb"

echo "[roundtrip] decoding with protoc ($($PROTOC --version))"
"$PROTOC" --decode=opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/metrics/v1/metrics_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"
cat "$TMP/decoded.txt"
echo "-------------------"

echo "[roundtrip] asserting expected fields round-tripped"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
assert 'key: "service.name"'
assert 'string_value: "spinel-app"'
assert 'name: "spinel-ebpf"'
assert 'name: "spnl_method_calls_total"'
assert 'as_int: 500'
assert 'key: "code.function"'
assert 'string_value: "fib"'
assert 'is_monotonic: true'
assert 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'
assert 'time_unix_nano: 1700000000000000000'

otlp_done "OTLP nanopb encode round-trips through protoc --decode"
