#!/usr/bin/env bash
#
# run_otlp_audit_span.sh -- wire verification of the audit span
# (spnl_otlp_audit_file_span). Turns a denied file access into a span, sends it to
# the mock receiver, and asserts through protoc decode: the span name, the kind,
# process.executable.path, process.parent.executable.path, file.path, verdict and
# Span.status=ERROR.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
PY="${PYTHON:-python3}"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_AUDIT_PORT:-18490}"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
echo "[audit] compiling audit-span test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_audit_span_test.c \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/audit"

"$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$TMP/pb.txt" \
  --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$TMP/pb.log" 2>&1 & SRV=$!
sleep 1
"$TMP/audit" "http://127.0.0.1:$PORT"
sleep 1
kill "$SRV" 2>/dev/null || true; SRV=""

echo "----- decoded (protobuf) -----"; sed -n '1,60p' "$TMP/pb.txt"; echo "------------------------------"
otlp_assert "$TMP/pb.txt" 'name: "file_open /etc/shadow"'
otlp_assert "$TMP/pb.txt" 'kind: SPAN_KIND_INTERNAL'
otlp_assert "$TMP/pb.txt" 'key: "process.executable.path"'
otlp_assert "$TMP/pb.txt" 'string_value: "/bin/cat"'
otlp_assert "$TMP/pb.txt" 'key: "process.parent.executable.path"'
otlp_assert "$TMP/pb.txt" 'string_value: "/usr/sbin/nginx"'
otlp_assert "$TMP/pb.txt" 'key: "file.path"'
otlp_assert "$TMP/pb.txt" 'string_value: "/etc/shadow"'
otlp_assert "$TMP/pb.txt" 'key: "verdict"'
otlp_assert "$TMP/pb.txt" 'string_value: "deny"'
otlp_assert "$TMP/pb.txt" 'code: STATUS_CODE_ERROR'

echo "PASS: OTLP audit span (deny/path/lineage -> semconv attributes + ERROR status)"
