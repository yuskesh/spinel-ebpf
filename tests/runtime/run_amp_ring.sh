#!/usr/bin/env bash
#
# run_amp_ring.sh -- host verification of the M7<->A55 shared ring -> OTLP logs.
#
# The producer (amp_emit) writes records carrying the common 16-byte event header
# into the ring; the consumer drains them and builds an OTLP
# ExportLogsServiceRequest. Single-producer/single-consumer wrap-around and
# full-drop are asserted inside the test binary; the payload it builds is checked
# here with protoc --decode for body, severity and service name.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
AMP="$REPO_ROOT/src/runtime/amp"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/deps/opentelemetry-proto}"
. "$REPO_ROOT/tests/runtime/proto_guard.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[amp-ring] compiling amp ring test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$REPO_ROOT/include" -I "$NANOPB" -I "$PB" -I "$OTLP" -I "$AMP" \
  tests/runtime/amp_ring_test.c \
  "$AMP/amp_otlp.c" \
  "$OTLP/otlp_logs.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" \
  "$OTLP/otlp_json.c" "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C -lz \
  -o "$TMP/amp_ring"

echo "[amp-ring] producer->ring->drain->OTLP logs -> $TMP/out.pb"
"$TMP/amp_ring" "$TMP/out.pb"

echo "[amp-ring] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/logs/v1/logs_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

echo "[amp-ring] asserting ring->LogRecord mapping (values 1,2,3 from amp_emit)"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
count()  { otlp_count  "$TMP/decoded.txt" "$1" "$2"; }
assert 'int_value: 1'
assert 'int_value: 2'
assert 'int_value: 3'
assert 'severity_number: SEVERITY_NUMBER_INFO'
assert 'string_value: "spinel-amp-m7"'
assert 'name: "spinel-amp-m7"'
count 'log_records {' 3

otlp_done "amp ring (16-byte-header records) -> A55 drain -> OTLP LogRecords"
