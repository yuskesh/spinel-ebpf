#!/usr/bin/env bash
#
# run_otlp_send.sh -- verification of the export transport.
#
# Sends the nanopb-encoded OTLP over a real TCP connection with otlp_http_post and
# asserts that the receiver answers 200 and decodes the body correctly.
#
# By default it uses the local mock receiver, so no real Collector is needed. To run
# against a real Collector:
#   OTLP_HOST=127.0.0.1 OTLP_PORT=4318 OTLP_NO_MOCK=1 sh tests/runtime/run_otlp_send.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/deps/opentelemetry-proto}"
. "$REPO_ROOT/tests/runtime/proto_guard.sh"
PY="${PYTHON:-python3}"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
HOST="${OTLP_HOST:-127.0.0.1}"
PORT="${OTLP_PORT:-14318}"        # the mock default; pass 4318 for a real Collector
TMP="$(mktemp -d)"
RECV_PID=""
cleanup() { [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[send] compiling send test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_send_test.c \
  "$OTLP/otlp_http.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -lz \
  -o "$TMP/otlp_send"

if [ "${OTLP_NO_MOCK:-0}" != "1" ]; then
  echo "[send] starting mock OTLP receiver on $HOST:$PORT"
  "$PY" tests/runtime/mock_otlp_receiver.py \
    --port "$PORT" --out "$TMP/decoded.txt" \
    --protoc "$PROTOC" --repo-root "$REPO_ROOT" &
  RECV_PID=$!
fi

echo "[send] sending (connect retries up to 5 times with backoff, to wait out receiver startup)"
"$TMP/otlp_send" "$HOST" "$PORT"
echo "[send] HTTP 200 received"

if [ "${OTLP_NO_MOCK:-0}" != "1" ]; then
  # the receiver writes decoded.txt while handling the POST, before it answers 200
  if [ ! -s "$TMP/decoded.txt" ]; then
    echo "[send] FAIL: receiver produced no decode output"; exit 1
  fi
  echo "[send] asserting receiver decoded the body"
  . "$REPO_ROOT/tests/runtime/otlp_common.sh"
  assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
  assert 'name: "spnl_method_calls_total"'
  assert 'as_int: 500'
  assert 'string_value: "spinel-app"'
  assert 'key: "code.function"'
  assert 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'
  if [ "$OTLP_FAIL" -ne 0 ]; then echo "[send] FAIL: decode mismatch"; exit 1; fi
fi

echo "[send] PASS: OTLP/HTTP+protobuf transport delivered & decoded"
