#!/usr/bin/env bash
#
# run_otlp_metric_series.sh -- the general keyed-metrics path: arbitrary labels,
# independent of --instrument.
# Sends two series (function=read/write plus a pid label) as OTLP metrics and checks
# that the receiver recovers the names, labels and counts. Both the protobuf and the
# JSON path are covered.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
PY="${PYTHON:-python3}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_METRIC_PORT:-18491}"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
echo "[metric] compiling generic keyed-metric test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_metric_test.c \
  "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/m"

start_mock() { "$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$1" \
  --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$2" 2>&1 & SRV=$!; }

echo "[metric] (1) protobuf: arbitrary labels + 2 series"
start_mock "$TMP/pb.txt" "$TMP/pb.log"
"$TMP/m" "http://127.0.0.1:$PORT"
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (protobuf) -----"; sed -n '1,30p' "$TMP/pb.txt"; echo "------------------------------"
otlp_assert "$TMP/pb.txt" 'name: "probe_calls"'
otlp_assert "$TMP/pb.txt" 'name: "probe_latency_ns"'
otlp_assert "$TMP/pb.txt" 'key: "function"'
otlp_assert "$TMP/pb.txt" 'string_value: "read"'
otlp_assert "$TMP/pb.txt" 'string_value: "write"'
otlp_assert "$TMP/pb.txt" 'key: "pid"'
otlp_assert "$TMP/pb.txt" 'as_int: 5'
otlp_assert "$TMP/pb.txt" 'as_int: 7'

echo "[metric] (2) JSON: arbitrary labels"
start_mock "$TMP/json.txt" "$TMP/json.log"
OTEL_EXPORTER_OTLP_PROTOCOL=http/json "$TMP/m" "http://127.0.0.1:$PORT"
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (json) -----"; cat "$TMP/json.txt"; echo; echo "--------------------------"
otlp_assert "$TMP/json.txt" '"probe_calls"'
otlp_assert "$TMP/json.txt" '"function"'
otlp_assert "$TMP/json.txt" '"read"'
otlp_assert "$TMP/json.txt" '"asInt":"5"'

otlp_done "OTLP general keyed metrics (arbitrary labels, independent of --instrument)"
