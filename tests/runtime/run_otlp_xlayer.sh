#!/usr/bin/env bash
#
# run_otlp_xlayer.sh -- verifies cross-layer (L2-L8) correlation within a single record.
# Builds a SERVER span from a real loopback fd and confirms in the JSON that
# L3 (client.address), L4 (server.port + net.tcp.established/state_changes),
# L7 (method/route/status), L8 (tenant) and the inherited trace context all sit on
# one span, i.e. one record. No libbpf dependency -- this is the span-builder path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/deps/opentelemetry-proto}"
. "$REPO_ROOT/tests/runtime/proto_guard.sh"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PY="${PYTHON:-python3}"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_XLAYER_PORT:-18491}"
TP="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
echo "[xlayer] compiling cross-layer span test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_xlayer_span_test.c \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/xlayer"

start_mock() { "$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$1" \
  --protoc "${PROTOC:-protoc}" --repo-root "$REPO_ROOT" >"$2" 2>&1 & SRV=$!; }

echo "[xlayer] (JSON) L3/L4 + L7 + L8 on a single span, plus traceId inheritance"
start_mock "$TMP/json.txt" "$TMP/json.log"
sleep 0.4
OTEL_EXPORTER_OTLP_PROTOCOL=http/json "$TMP/xlayer" "http://127.0.0.1:$PORT" "$TP" "acme" 1 3 200
sleep 0.2
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- correlated record (json) -----"; cat "$TMP/json.txt"; echo; echo "------------------------------------"
# L7
otlp_assert "$TMP/json.txt" '"kind":2'                       # SERVER span
otlp_assert "$TMP/json.txt" '"http.request.method"'
otlp_assert "$TMP/json.txt" '"url.path"'
otlp_assert "$TMP/json.txt" '"http.route"'
otlp_assert "$TMP/json.txt" '"http.response.status_code"'
# L3 / L4 (addressing, plus the cross-layer 4-tuple keyed metrics)
otlp_assert "$TMP/json.txt" '"client.address"'              # L3 src ip
otlp_assert "$TMP/json.txt" '"server.port"'                 # L4 dst port
otlp_assert "$TMP/json.txt" '"net.tcp.established"'         # L4 4-tuple keyed
otlp_assert "$TMP/json.txt" '"net.tcp.state_changes"'      # L4 4-tuple keyed
# L8 (business context) plus trace inheritance
otlp_assert "$TMP/json.txt" '"tenant"'
otlp_assert "$TMP/json.txt" '"stringValue":"acme"'
otlp_assert "$TMP/json.txt" '"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"'   # continues the incoming trace
otlp_assert "$TMP/json.txt" '"parentSpanId":"00f067aa0ba902b7"'

echo "[xlayer] (protobuf) the same attributes come through the protobuf path"
start_mock "$TMP/pb.txt" "$TMP/pb.log"
sleep 0.4
"$TMP/xlayer" "http://127.0.0.1:$PORT" "$TP" "acme" 2 5 200
sleep 0.2
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- correlated record (protobuf) -----"; sed -n '1,80p' "$TMP/pb.txt"; echo "----------------------------------------"
otlp_assert "$TMP/pb.txt" 'key: "tenant"'
otlp_assert "$TMP/pb.txt" 'string_value: "acme"'
otlp_assert "$TMP/pb.txt" 'key: "net.tcp.established"'
otlp_assert "$TMP/pb.txt" 'key: "net.tcp.state_changes"'
otlp_assert "$TMP/pb.txt" 'key: "client.address"'
otlp_assert "$TMP/pb.txt" 'key: "server.port"'

if [ "$OTLP_FAIL" = 0 ]; then echo "[xlayer] PASS"; else echo "[xlayer] FAIL"; exit 1; fi
