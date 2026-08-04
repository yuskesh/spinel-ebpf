#!/bin/sh
# Form gate: spinel-ebpf is a FORM of spinel, not a fork of it.
#
# The claim this gate defends: opting into spinel-ebpf never costs you spinel.
# Concretely, for a program with no eBPF partition, `spinel-ebpf compile
# --native-only` must produce a .c that is byte-identical to upstream's
# `spinel -c`. If that ever drifts, spinel-ebpf has silently become a fork, and
# the portability contract -- the native side is upstream spinel unchanged, and
# only the eBPF side adds requirements of its own -- no longer holds.
#
# Run inside the build container (needs the Linux spinel ELF):
#   sh tools/form_verify.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPINEL="${SPINEL_C_BIN:-$ROOT/deps/spinel/bin/spinel}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$SPINEL" ]; then
  echo "form_verify: upstream spinel not built at $SPINEL (run: sh scripts/setup.sh)" >&2
  exit 1
fi

# Fixtures without an eBPF partition: their whole output is the native side, so
# byte-identity is the strongest possible statement of the "one form" property.
FIXTURES="${*:-$ROOT/tests/fixtures/01_hello.rb $ROOT/tests/fixtures/02_integer_arith.rb $ROOT/tests/fixtures/03_fib_recursion.rb}"

pass=0
fail=0
for rb in $FIXTURES; do
  base="$(basename "$rb" .rb)"
  mkdir -p "$WORK/$base"
  "$SPINEL" "$rb" -c -o "$WORK/$base/upstream.c" >/dev/null 2>&1
  "$ROOT/bin/spinel-ebpf" compile "$rb" --native-only -o "$WORK/$base" >/dev/null 2>&1
  if cmp -s "$WORK/$base/upstream.c" "$WORK/$base/$base.c"; then
    pass=$((pass + 1))
    echo "  OK    $base  (--native-only == spinel -c)"
  else
    fail=$((fail + 1))
    echo "  DRIFT $base" >&2
    diff "$WORK/$base/upstream.c" "$WORK/$base/$base.c" | head -20 >&2 || true
  fi
done

echo "------------------------------------------------------------"
echo "form: --native-only vs upstream spinel -c   IDENTICAL=$pass  DRIFT=$fail"
[ "$fail" -eq 0 ]
