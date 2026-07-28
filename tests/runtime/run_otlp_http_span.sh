#!/usr/bin/env bash
#
# run_otlp_http_span.sh -- HTTP server span and W3C traceparent propagation.
# Sends a SERVER span with a known traceparent and checks that the mock receiver
# recovers trace_id, parent, kind and the http.* attributes. Both paths are covered:
# protobuf (attributes, kind, name) and JSON (the hex trace_id and parent matching
# the incoming values exactly).
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
PORT="${OTLP_SPAN_PORT:-18488}"
TP="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
echo "[span] compiling http-span test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_http_span_test.c \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/span"

start_mock() { "$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$1" \
  --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$2" 2>&1 & SRV=$!; }

echo "[span] (1) protobuf: SERVER span + http.* attributes + name + the extra semconv attributes + the resource sdk attributes"
start_mock "$TMP/pb.txt" "$TMP/pb.log"
"$TMP/span" "http://127.0.0.1:$PORT" "$TP" 200 /hello
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (protobuf) -----"; sed -n '1,60p' "$TMP/pb.txt"; echo "------------------------------"
otlp_assert "$TMP/pb.txt" 'name: "GET /hello"'
otlp_assert "$TMP/pb.txt" 'kind: SPAN_KIND_SERVER'
otlp_assert "$TMP/pb.txt" 'key: "http.request.method"'
otlp_assert "$TMP/pb.txt" 'string_value: "GET"'
otlp_assert "$TMP/pb.txt" 'key: "url.path"'
otlp_assert "$TMP/pb.txt" 'string_value: "/hello"'
otlp_assert "$TMP/pb.txt" 'int_value: 200'
# extra attributes for compatibility with semconv v1.41.0 and the OpenTelemetry eBPF instrumentation
otlp_assert "$TMP/pb.txt" 'key: "server.address"'
otlp_assert "$TMP/pb.txt" 'string_value: "127.0.0.1"'
otlp_assert "$TMP/pb.txt" 'key: "server.port"'
otlp_assert "$TMP/pb.txt" 'key: "client.address"'
otlp_assert "$TMP/pb.txt" 'key: "url.scheme"'
otlp_assert "$TMP/pb.txt" 'string_value: "http"'
otlp_assert "$TMP/pb.txt" 'key: "http.route"'
# resource attributes, shared by every signal
otlp_assert "$TMP/pb.txt" 'key: "service.instance.id"'
otlp_assert "$TMP/pb.txt" 'key: "telemetry.sdk.name"'
otlp_assert "$TMP/pb.txt" 'string_value: "spinel-ebpf"'
otlp_assert "$TMP/pb.txt" 'key: "telemetry.sdk.language"'
otlp_assert "$TMP/pb.txt" 'string_value: "ruby"'

echo "[span] (2) JSON: traceId/parentSpanId match the incoming traceparent exactly (propagation proven)"
start_mock "$TMP/json.txt" "$TMP/json.log"
OTEL_EXPORTER_OTLP_PROTOCOL=http/json "$TMP/span" "http://127.0.0.1:$PORT" "$TP" 200 /hello
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (json) -----"; cat "$TMP/json.txt"; echo; echo "--------------------------"
otlp_assert "$TMP/json.txt" '"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"'   # continues the incoming trace
otlp_assert "$TMP/json.txt" '"parentSpanId":"00f067aa0ba902b7"'              # the incoming span is the parent
otlp_assert "$TMP/json.txt" '"kind":2'
otlp_assert "$TMP/json.txt" '"http.request.method"'
otlp_assert "$TMP/json.txt" '"url.path"'
otlp_assert "$TMP/json.txt" '"server.address"'
otlp_assert "$TMP/json.txt" '"url.scheme"'
otlp_assert "$TMP/json.txt" '"http.route"'
otlp_assert "$TMP/json.txt" '"service.instance.id"'
otlp_assert "$TMP/json.txt" '"telemetry.sdk.name"'

echo "[span] (3) protobuf: status=500 makes Span.status = STATUS_CODE_ERROR"
start_mock "$TMP/err.txt" "$TMP/err.log"
"$TMP/span" "http://127.0.0.1:$PORT" "$TP" 500 /boom || true
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (protobuf, 500) -----"; sed -n '1,60p' "$TMP/err.txt"; echo "-----------------------------------"
otlp_assert "$TMP/err.txt" 'code: STATUS_CODE_ERROR'
otlp_assert "$TMP/err.txt" 'int_value: 500'

otlp_done "OTLP HTTP server span + W3C traceparent propagation + semconv v1.41.0 agreement"
