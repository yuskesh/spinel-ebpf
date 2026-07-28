#!/usr/bin/env bash
#
# run_otlp_tls.sh -- sends OTLP straight over TLS with mbedTLS, both https://
# (OTLP/HTTP) and grpcs:// (OTLP/gRPC), and verifies that the TLS-terminating mock
# can recover the protobuf. That is TLS plus OTLP end to end.
# It also confirms the auth header and gzip still take effect over TLS.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
PY="${PYTHON:-python3}"
VENV_PY="${VENV_PY:-$REPO_ROOT/.venv-otlp/bin/python}"   # grpcio, for the grpcs mock
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
MBED="$REPO_ROOT/third_party/mbedtls"
PROTO_ROOT="$REPO_ROOT/third_party/opentelemetry-proto"
PORT="${OTLP_TLS_PORT:-18444}"
GPORT="${OTLP_GRPCS_PORT:-18454}"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

sh "$REPO_ROOT/scripts/build-mbedtls.sh" >/dev/null
PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[t1] self-signed cert (CN=localhost)"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
cat "$TMP/cert.pem" "$TMP/key.pem" > "$TMP/srv.pem"

echo "[t1] compiling https sender (-DOTLP_WITH_TLS + mbedTLS + zlib)"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -DOTLP_WITH_TLS \
  -I "$NANOPB" -I "$PB" -I "$OTLP" -I "$MBED/include" \
  tests/runtime/otlp_tls_send_test.c \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" "$OTLP/otlp_tls.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C \
  "$MBED/library/libmbedtls.a" "$MBED/library/libmbedx509.a" "$MBED/library/libmbedcrypto.a" \
  -lz -o "$TMP/tls_send"

echo "[t1] starting TLS OTLP mock (https)"
"$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$TMP/dec.txt" \
  --cert "$TMP/srv.pem" --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$TMP/recv.log" 2>&1 &
SRV=$!

echo "[t1] send https:// (verify with self-signed CA) + auth header + gzip"
OTEL_EXPORTER_OTLP_CERTIFICATE="$TMP/cert.pem" \
OTEL_EXPORTER_OTLP_HEADERS="x-sf-token=tls-token-42" \
OTEL_EXPORTER_OTLP_COMPRESSION=gzip \
  "$TMP/tls_send" "https://localhost:$PORT"
kill "$SRV" 2>/dev/null || true; SRV=""

echo "----- decoded over TLS -----"; cat "$TMP/dec.txt" 2>/dev/null | head -20; echo "----------------------------"
otlp_assert "$TMP/dec.txt" 'name: "spnl_method_calls_total"'   # OTLP arrived over TLS and decoded
otlp_assert "$TMP/dec.txt" 'as_int: 500'
if grep -qi "gunzip ->" "$TMP/recv.log"; then echo "  ok: gzip over TLS"; else echo "  MISSING: gzip"; OTLP_FAIL=1; fi
if grep -qi "header x-sf-token: tls-token-42" "$TMP/recv.log"; then echo "  ok: auth header over TLS"; else echo "  MISSING: auth header"; OTLP_FAIL=1; fi

# ---- T2: grpcs:// (gRPC over TLS) ----
if [ -x "$VENV_PY" ]; then
  echo "[t2] starting TLS gRPC mock (grpcs)"
  "$VENV_PY" tests/runtime/mock_otlp_grpc.py --port "$GPORT" --out "$TMP/gdec.txt" \
    --cert "$TMP/cert.pem" --key "$TMP/key.pem" --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$TMP/grecv.log" 2>&1 &
  SRV=$!
  echo "[t2] send grpcs:// (verify with self-signed CA) + auth header + gzip"
  OTEL_EXPORTER_OTLP_CERTIFICATE="$TMP/cert.pem" \
  OTEL_EXPORTER_OTLP_HEADERS="x-sf-token=grpcs-token-7" \
  OTEL_EXPORTER_OTLP_COMPRESSION=gzip \
    "$TMP/tls_send" "grpcs://localhost:$GPORT"
  kill "$SRV" 2>/dev/null || true; SRV=""
  echo "----- decoded over grpcs -----"; head -8 "$TMP/gdec.txt" 2>/dev/null; echo "------------------------------"
  otlp_assert "$TMP/gdec.txt" 'name: "spnl_method_calls_total"'   # OTLP arrived over grpcs and decoded
  if grep -qi "meta x-sf-token: grpcs-token-7" "$TMP/grecv.log"; then echo "  ok: auth metadata over grpcs"; else echo "  MISSING: grpcs auth metadata"; OTLP_FAIL=1; fi
else
  echo "[t2] SKIP grpcs (no venv grpcio at $VENV_PY)"
fi

# ---- mTLS (client cert) ----
echo "[mtls] generating client cert (CN=spinel-client)"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/clik.pem" -out "$TMP/clic.pem" \
  -days 1 -nodes -subj "/CN=spinel-client" >/dev/null 2>&1
MPORT="${OTLP_MTLS_PORT:-18464}"
echo "[mtls] starting TLS OTLP mock requiring client cert"
"$PY" tests/runtime/mock_otlp_receiver.py --port "$MPORT" --out "$TMP/mdec.txt" \
  --cert "$TMP/srv.pem" --client-ca "$TMP/clic.pem" --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$TMP/mrecv.log" 2>&1 &
SRV=$!
echo "[mtls] (1) send WITH client cert -> expect 200"
OTEL_EXPORTER_OTLP_CERTIFICATE="$TMP/cert.pem" \
OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="$TMP/clic.pem" \
OTEL_EXPORTER_OTLP_CLIENT_KEY="$TMP/clik.pem" \
  "$TMP/tls_send" "https://localhost:$MPORT"
otlp_assert "$TMP/mdec.txt" 'name: "spnl_method_calls_total"'   # OTLP arrived over mTLS
echo "[mtls] (2) send WITHOUT client cert -> expect REJECT"
if OTEL_EXPORTER_OTLP_CERTIFICATE="$TMP/cert.pem" "$TMP/tls_send" "https://localhost:$MPORT" 2>/dev/null; then
  echo "  FAIL: server accepted without client cert"; OTLP_FAIL=1
else
  echo "  ok (rejected -- the server really is requiring mTLS)"
fi
kill "$SRV" 2>/dev/null || true; SRV=""

otlp_done "OTLP over HTTPS + grpcs + mTLS (mbedTLS), sent directly, with auth + gzip"
