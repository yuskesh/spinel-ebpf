#!/usr/bin/env bash
#
# run_amp_s3.sh -- one-command `--target amp-m7 --build` plus the manifest-driven drain.
#
#   1. CLI:   spinel-ebpf compile hb_hw.rb --target amp-m7 --build  -> hb_hw.blob + hb_hw.manifest
#   2. drain: the FIXED, probe-independent A55 drain reads service.name from the
#             manifest and turns a ring (synthetic 7,14,21 = the M7 blob's output)
#             into an OTLP logs payload.
#   3. verify: protoc --decode asserts the service.name came FROM the manifest and
#             the values are 7,14,21.
#
# Needs (Linux/container): ruby, clang (-target bpf), the in-process codegen, protoc,
# and the micro-bpf host AOT driver (SPNL_AMP_AOT_DRIVER, or built via cargo). If the
# driver / cargo is unavailable the CLI step is SKIPped (drain logic still checked
# against a committed manifest).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
SPINEL_DIR="${SPINEL_DIR:-$REPO_ROOT/deps/spinel}"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
AMP="$REPO_ROOT/src/runtime/amp"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/deps/opentelemetry-proto}"
. "$REPO_ROOT/tests/runtime/proto_guard.sh"
ICC="$REPO_ROOT/build/codegen_c/spinel-ebpf-cc"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SERVICE="spinel-amp-test"   # distinct so the assert proves it came from the manifest

# --- locate/build the AOT driver ---
# target/ is bind-mounted (like build/), so it may hold a wrong-platform ELF.
# Preflight: run with no args -- a runnable driver panics (exit 101), a wrong-arch
# ELF fails to exec (126/127).
runs_here() { "$1" >/dev/null 2>&1; local rc=$?; [ "$rc" != 126 ] && [ "$rc" != 127 ]; }
locate_driver() {
  for c in "${SPNL_AMP_AOT_DRIVER:-}" \
           "$REPO_ROOT/tools/amp_aot_driver/target/release/aot-driver"; do
    [ -n "$c" ] && [ -x "$c" ] && runs_here "$c" && { echo "$c"; return 0; }
  done
  return 1
}
DRV="$(locate_driver || true)"
if [ -z "$DRV" ] && command -v cargo >/dev/null 2>&1; then
  echo "[amp-build] building AOT driver (cargo)"
  ( cd "$REPO_ROOT/tools/amp_aot_driver" \
    && CARGO_HOME=/tmp/cargo-home CARGO_TARGET_DIR=/tmp/amp_driver_s3 cargo build --release >/dev/null 2>&1 ) || true
  [ -x /tmp/amp_driver_s3/release/aot-driver ] && DRV=/tmp/amp_driver_s3/release/aot-driver
fi

MANIFEST=""
if [ -n "$DRV" ] && [ -x "$ICC" ]; then
  echo "[amp-build] CLI 1-command: hb_hw.rb --target amp-m7 --build (driver=$DRV)"
  SPNL_AMP_AOT_DRIVER="$DRV" LANG=C.UTF-8 \
    ruby bin/spinel-ebpf compile examples/observability/amp/hb_hw.rb \
      --target amp-m7 --build -o "$TMP" --amp-service-name "$SERVICE" 2>&1 \
    | grep -E "amp-m7 --build|helper id" | sed 's/^/     /'
  [ -s "$TMP/hb_hw.blob" ] || { echo "[amp-build] FAIL: CLI produced no blob"; exit 1; }
  [ -s "$TMP/hb_hw.manifest" ] || { echo "[amp-build] FAIL: CLI produced no manifest"; exit 1; }
  echo "[amp-build] blob = $(wc -c < "$TMP/hb_hw.blob") bytes; manifest:"; sed 's/^/       /' "$TMP/hb_hw.manifest"
  MANIFEST="$TMP/hb_hw.manifest"
else
  # Without the ahead-of-time driver and the in-process code generator there is
  # nothing to build a manifest from, and this harness drives everything else off
  # that manifest. Skip rather than assert against a stand-in.
  echo "[amp-build] SKIP: no AOT driver or in-process codegen available"
  exit 0
fi

# --- fixed, manifest-driven drain -> OTLP payload (host; no /dev/mem, no network) ---
echo "[amp-build] building manifest-driven drain test"
PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$REPO_ROOT/include" -I "$NANOPB" -I "$PB" -I "$OTLP" -I "$AMP" \
  tests/runtime/amp_s3_drain_test.c \
  "$AMP/amp_manifest.c" "$AMP/amp_otlp.c" \
  "$OTLP/otlp_logs.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" \
  "$OTLP/otlp_json.c" "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C -lz \
  -o "$TMP/drain"

echo "[amp-build] drain: manifest -> ring(7,14,21) -> OTLP -> $TMP/out.pb"
"$TMP/drain" "$MANIFEST" "$TMP/out.pb"

echo "[amp-build] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest \
  -I "$PROTO_ROOT" opentelemetry/proto/collector/logs/v1/logs_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"
echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
count()  { otlp_count  "$TMP/decoded.txt" "$1" "$2"; }
echo "[amp-build] asserting service.name FROM manifest ('$SERVICE') + values 7,14,21"
assert "string_value: \"$SERVICE\""    # service.name flowed from the manifest
assert 'int_value: 7'
assert 'int_value: 14'
assert 'int_value: 21'
count 'log_records {' 3

otlp_done "amp-m7 --build (blob+manifest, 1 command) -> fixed manifest-driven drain -> OTLP logs"
