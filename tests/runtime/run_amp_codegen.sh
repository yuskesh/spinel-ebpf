#!/usr/bin/env bash
#
# run_amp_codegen.sh -- the supported/unsupported gate for the amp-m7 codegen.
#
# - supported (blink / heartbeat): SPNL_AMP_M7 codegen succeeds and emits the
#   expected C
# - unsupported (hist_observe / path_counter_inc / spnl_emit_str): the amp builtin
#   allowlist makes codegen die loudly, naming the builtin, rather than letting it
#   leak through to clang
#
# Requires a built spinel (the in-process codegen binary). Run inside a container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

SPINEL_DIR="${SPINEL_DIR:-$REPO_ROOT/third_party/spinel}"
ICC="$REPO_ROOT/build/codegen_c/spinel-ebpf-cc"
if [ ! -x "$ICC" ]; then
  echo "[amp] building in-process codegen"
  OBJ=$(ls "$SPINEL_DIR"/build/csrc/*.o | grep -v '/main\.o$' | tr '\n' ' ')
  mkdir -p "$REPO_ROOT/build/codegen_c"
  # shellcheck disable=SC2086
  cc -O2 -I "$SPINEL_DIR/src" "$REPO_ROOT/tools/spinel_ebpf_inproc.c" $OBJ \
     "$SPINEL_DIR/build/libprism.a" -lm -o "$ICC"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

# Text-only check that the AMP_*_MIRROR constants in the codegen have not drifted
# from the fixed ABI header. spinel_ebpf_cc.c avoids -Iinclude and therefore mirrors
# the header's values instead of #including it -- this is what keeps the two in sync.
echo "[amp] fixed-ABI mirror drift check (spinel_ebpf_cc.c == spnl/amp_abi_imx95m7.h)"
abi_hdr="include/spnl/amp_abi_imx95m7.h"
cc_src="src/codegen_c/spinel_ebpf_cc.c"
hdr_ver=$(grep -oE '#define AMP_ABI_VERSION[[:space:]]+[0-9]+u' "$abi_hdr" | grep -oE '[0-9]+u$')
cc_ver=$(grep -oE '#define AMP_ABI_VERSION_MIRROR[[:space:]]+[0-9]+u' "$cc_src" | grep -oE '[0-9]+u$')
hdr_base=$(grep -oE '#define AMP_IVARS_BASE[[:space:]]+0x[0-9A-Fa-f]+u' "$abi_hdr" | grep -oE '0x[0-9A-Fa-f]+u$' | tr 'A-F' 'a-f')
cc_base=$(grep -oE '#define AMP_IVARS_BASE_MIRROR[[:space:]]+0x[0-9A-Fa-f]+u' "$cc_src" | grep -oE '0x[0-9A-Fa-f]+u$' | tr 'A-F' 'a-f')
if [ -n "$hdr_ver" ] && [ "$hdr_ver" = "$cc_ver" ] && [ -n "$hdr_base" ] && [ "$hdr_base" = "$cc_base" ]; then
  echo "  ok: AMP_ABI_VERSION=$hdr_ver AMP_IVARS_BASE=$hdr_base (mirror in sync)"
else
  echo "  FAIL(drift): header ver=$hdr_ver base=$hdr_base vs mirror ver=$cc_ver base=$cc_base"; fail=1
fi

emit() { SPNL_AMP_M7=1 "$ICC" "$1" amp 2>"$TMP/err"; }   # stdout=C, stderr=diag

echo "[amp] supported probes must succeed"
for rb in examples/observability/amp/blink.rb examples/observability/amp/heartbeat.rb; do
  if emit "$rb" > "$TMP/out.c"; then
    grep -q "amp_emit(" "$TMP/out.c" && echo "  ok: $rb" || { echo "  FAIL(no amp_emit): $rb"; fail=1; }
  else
    echo "  FAIL(die): $rb -> $(cat "$TMP/err")"; fail=1
  fi
done

echo "[amp] unsupported builtins must die at codegen (not leak to clang)"
check_die() {  # $1=ruby-body-call  $2=expected-name-in-message
  printf 'def timer_100\n  %s\nend\n' "$1" > "$TMP/u.rb"
  if emit "$TMP/u.rb" > /dev/null; then
    echo "  FAIL(no die): $1"; fail=1
  elif grep -q "does not support '$2'" "$TMP/err"; then
    echo "  ok: '$1' -> die naming '$2'"
  else
    echo "  FAIL(wrong msg): $1 -> $(cat "$TMP/err")"; fail=1
  fi
}
check_die 'hist_observe(42)'      'hist_observe'
check_die 'path_counter_inc(1)'   'path_counter_inc'
check_die 'spnl_emit_str("hi")'   'spnl_emit_str'

echo "[amp] ktime_ns is a supported amp helper"
printf 'def timer_100\n  spnl_emit(ktime_ns)\nend\n' > "$TMP/k.rb"
if emit "$TMP/k.rb" > "$TMP/k.c" && grep -q 'amp_ktime()' "$TMP/k.c"; then
  echo "  ok: ktime_ns -> amp_ktime()"
else
  echo "  FAIL: ktime_ns not lowered to amp_ktime -> $(cat "$TMP/err")"; fail=1
fi

if [ "$fail" -eq 0 ]; then echo "PASS: amp-m7 codegen supported/unsupported gate"; else echo "FAIL"; exit 1; fi
