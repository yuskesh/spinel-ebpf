#!/usr/bin/env bash
#
# run_amp_trace.sh -- correlates M7 events with an A55 request span through a PHC
# time window (a cross-core trace).
#
# Decodes the ExportTraceServiceRequest that amp_ring_drain_trace builds with
# protoc --decode, then asserts the parent request span plus the in-window M7
# child spans (shared trace_id, matching parent_span_id).
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

echo "[amp-trace] compiling amp trace test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$REPO_ROOT/include" -I "$NANOPB" -I "$PB" -I "$OTLP" -I "$AMP" \
  tests/runtime/amp_trace_test.c \
  "$AMP/amp_otlp.c" \
  "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" "$OTLP/otlp_logs.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C -lz \
  -o "$TMP/amp_trace"

echo "[amp-trace] M7 ring -> A55-correlated trace -> $TMP/out.pb"
"$TMP/amp_trace" "$TMP/out.pb"

echo "[amp-trace] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/trace/v1/trace_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

echo "[amp-trace] asserting cross-core correlation (parent request + in-window M7 children)"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
count()  { otlp_count  "$TMP/decoded.txt" "$1" "$2"; }
assert 'name: "GET /fetch"'          # A55 request (parent)
count  'name: "amp.emit"' 3          # 3 M7 event spans (2 in-window + 1 out)
assert 'string_value: "11"'          # in-window value
assert 'string_value: "22"'          # in-window value
assert 'string_value: "33"'          # out-of-window value (standalone)
assert 'key: "amp.value"'
# cross-core correlation: the request trace_id appears 3x (request + its 2 in-window
# children); the out-of-window record is a standalone root with a different trace_id.
count  'trace_id: "\240\241\242\243\244\245\246\247\250\251\252\253\254\255\256\257"' 3
# exactly the 2 in-window children carry a parent_span_id (= the request span_id):
count  'parent_span_id:' 2

otlp_done "M7 events correlated to A55 request span on the PHC time axis"
