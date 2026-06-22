#!/bin/sh
# Regenerate tests/fixtures/*.{ast,ir} from tests/fixtures/*.rb using the current
# spinel plus the spinel-ebpf in-process codegen:
#   - .ast : spinel --dump-ast --no-line-map  (the parsed AST the partition reads)
#   - .ir  : the in-process codegen's --ir mode (cc_build_ir_text over the analyzed
#            Compiler) -- the method-signature IR the partition/dispatch consume.
#
# Run INSIDE the build container with the project mounted at /work, after spinel
# is built (cd deps/spinel && make deps && make). Works on any Linux host
# with a built spinel in $SPINEL_DIR.
#
# Re-running this should leave tests/fixtures/ unchanged; if a spinel update shifts
# the output, regenerate and re-run the unit suite -- a few tests assert the exact
# codegen/IR shape (the return type of attach/conditional handler inners, the
# per-local scope records, the program-capability flags) and may need updating.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPINEL_DIR="${SPINEL_DIR:-$ROOT/deps/spinel}"
FIX_DIR="$ROOT/tests/fixtures"
SPINEL="$SPINEL_DIR/build/spinel"
CC_BIN="$ROOT/build/codegen_c/spinel-ebpf-cc"

if [ ! -x "$SPINEL" ]; then
  echo "error: $SPINEL not found — build first (cd $SPINEL_DIR && make)" >&2
  exit 1
fi

# Build the in-process codegen binary (upstream objects minus main.o + the
# codegen TU with -DSPNL_INPROCESS). Mirrors bin/spinel-ebpf's inproc_codegen_bin.
OBJ=$(ls "$SPINEL_DIR"/build/csrc/*.o | grep -v '/main\.o$' | tr '\n' ' ')
mkdir -p "$ROOT/build/codegen_c"
# shellcheck disable=SC2086
cc -O2 -I "$SPINEL_DIR/src" "$ROOT/tools/spinel_ebpf_inproc.c" $OBJ \
   "$SPINEL_DIR/build/libprism.a" -lm -o "$CC_BIN"

cd "$ROOT"
count=0
for rb in "$FIX_DIR"/*.rb; do
  base="$(basename "$rb" .rb)"
  # Relative path keeps spinel's SOURCE_FILE line portable across machines/dirs.
  rel_rb="${rb#"$ROOT"/}"
  "$SPINEL" --dump-ast --no-line-map "$rel_rb" > "$FIX_DIR/$base.ast"
  "$CC_BIN" "$rel_rb" "$base" --ir                > "$FIX_DIR/$base.ir"
  count=$((count + 1))
  echo "regenerated: $base.{ast,ir}"
done
echo "done: $count fixtures regenerated"
