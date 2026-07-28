#!/usr/bin/env bash
#
# run_otlp_tls_smoke.sh -- builds the vendored mbedTLS and verifies the TLS client
# handshake.
#   1) verification ON with the self-signed CA (OTEL_EXPORTER_OTLP_CERTIFICATE)
#                                                       -> handshake succeeds
#   2) INSECURE_SKIP_VERIFY=1                           -> handshake succeeds
#   3) verification ON with no CA supplied, so only the system CAs, which do not
#      trust a self-signed cert                         -> handshake fails, which is
#      what proves verification is actually happening
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PY="${PYTHON:-python3}"
MBED="$REPO_ROOT/third_party/mbedtls"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_TLS_PORT:-18443}"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

# Build the mbedTLS static libraries. An architecture stamp keeps a host build and
# a container build from being mistaken for each other.
sh "$REPO_ROOT/scripts/build-mbedtls.sh" >/dev/null

echo "[t0] generating self-signed cert (CN=localhost)"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
cat "$TMP/cert.pem" "$TMP/key.pem" > "$TMP/srv.pem"

echo "[t0] compiling otlp_tls smoke (link mbedTLS .a)"
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$OTLP" -I "$MBED/include" \
  tests/runtime/otlp_tls_smoke.c "$OTLP/otlp_tls.c" \
  "$MBED/library/libmbedtls.a" "$MBED/library/libmbedx509.a" "$MBED/library/libmbedcrypto.a" \
  -o "$TMP/tls_smoke"

echo "[t0] starting HTTPS mock"
"$PY" tests/runtime/mock_tls_server.py "$PORT" "$TMP/srv.pem" >/tmp/.tls_mock.log 2>&1 &
SRV=$!
# readiness: poll the port instead of sleeping
for _ in $(seq 1 100); do "$PY" -c "import socket;socket.create_connection(('127.0.0.1',$PORT),0.1)" 2>/dev/null && break || true; done

fail=0
echo "[t0] (1) verify ON + self-signed CA -> expect OK"
if OTEL_EXPORTER_OTLP_CERTIFICATE="$TMP/cert.pem" "$TMP/tls_smoke" localhost "$PORT"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "[t0] (2) INSECURE_SKIP_VERIFY=1 -> expect OK"
if OTEL_EXPORTER_OTLP_INSECURE_SKIP_VERIFY=1 "$TMP/tls_smoke" localhost "$PORT"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "[t0] (3) verify ON with system CAs only (self-signed is untrusted) -> expect REJECT"
if "$TMP/tls_smoke" localhost "$PORT" 2>/dev/null; then
  # the system CAs do not trust a self-signed cert, so verification must fail the handshake
  echo "  FAIL: should have rejected self-signed under system CA"; fail=1
else
  echo "  ok (rejected as expected -- verification is doing its job)"
fi

[ "$fail" -eq 0 ] && echo "[t0] PASS: mbedTLS build + TLS client handshake & verify" || { echo "[t0] FAIL"; exit 1; }
