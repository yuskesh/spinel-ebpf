#!/usr/bin/env bash
#
# run_otlp_grpc.sh -- verification of the OTLP/gRPC transport.
#
# Sends the sample metrics with the hand-written HTTP/2 gRPC client and asserts that
# the grpcio mock can decode the request. A successful decode means the HTTP/2,
# HPACK and gRPC framing are all correct.
# The mock needs grpcio, so it runs under the venv python.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
VENV_PY="${VENV_PY:-$REPO_ROOT/.venv-otlp/bin/python}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_GRPC_PORT:-14317}"
TMP="$(mktemp -d)"
RECV_PID=""
cleanup() { [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[grpc] compiling gRPC client test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_grpc_test.c \
  "$OTLP/otlp_grpc.c" "$OTLP/otlp_http.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -lz \
  -o "$TMP/otlp_grpc"

echo "[grpc] starting grpcio mock on 127.0.0.1:$PORT (venv python)"
"$VENV_PY" tests/runtime/mock_otlp_grpc.py \
  --port "$PORT" --out "$TMP/decoded.txt" --protoc "$PROTOC" --repo-root "$REPO_ROOT" &
RECV_PID=$!

echo "[grpc] sending (connect retries cover mock startup)"
"$TMP/otlp_grpc" 127.0.0.1 "$PORT"
echo "[grpc] gRPC stream completed ok"

# The mock writes decoded.txt once it has handled the unary call; poll for it rather than sleeping.
ok=0
for _ in $(seq 1 100); do
  if [ -s "$TMP/decoded.txt" ]; then ok=1; break; fi
  "$VENV_PY" -c "pass" >/dev/null 2>&1 || true
done
if [ "$ok" != 1 ]; then echo "[grpc] FAIL: mock produced no decode output"; exit 1; fi

echo "----- mock decoded -----"; cat "$TMP/decoded.txt"; echo "------------------------"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
assert 'name: "spnl_method_calls_total"'
assert 'as_int: 500'
assert 'string_value: "spinel-app"'
assert 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'
otlp_done "OTLP/gRPC (hand-rolled HTTP/2) delivered & decoded by grpcio"
