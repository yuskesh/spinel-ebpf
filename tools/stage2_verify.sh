#!/bin/sh
# In-process codegen gate. Run INSIDE the build container (spnlbuild),
# cwd = repo root. Confirms the PRODUCTION in-process codegen (parse+analyze
# .rb -> Compiler -> emit, no --emit-ir) reproduces the committed goldens
# (tests/golden/*.bpf.c) byte-for-byte — the same goldens the host gate
# (tools/golden.rb) pins the text codegen to. Together: golden.rb gates the
# codegen logic on the host; this gates that the in-process path == golden.
#
# (Previously this diffed the in-process output against the Ruby CodegenBpf
#  oracle; that lockstep is retired — the goldens are the source of truth now.
#  See tools/golden.rb / tools/cgen_oracle.rb.)
set -eu
cd "$(dirname "$0")/.."
SP=deps/spinel
mkdir -p build/codegen_c

make -C "$SP" >/dev/null 2>&1 || { echo "spinel build failed"; exit 1; }
OBJ=$(ls "$SP"/build/csrc/*.o | grep -v '/main\.o$' | tr '\n' ' ')

# In-process codegen binary (#include's the codegen TU with -DSPNL_INPROCESS).
cc -O2 -Wall -Wextra -I "$SP/src" \
   tools/spinel_ebpf_inproc.c $OBJ "$SP"/build/libprism.a -lm \
   -o build/codegen_c/spinel-ebpf-cc

pass=0; mism=0; skip=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for rb in tests/fixtures/*.rb; do
  base=$(basename "$rb" .rb)
  golden="tests/golden/$base.bpf.c"
  [ -f "$golden" ] || { skip=$((skip + 1)); continue; }   # no golden = no eBPF programs
  if build/codegen_c/spinel-ebpf-cc "$rb" "$base" > "$tmp/inproc.bpf.c" 2>/dev/null \
     && cmp -s "$golden" "$tmp/inproc.bpf.c"; then
    pass=$((pass + 1))
  else
    mism=$((mism + 1)); echo "MISMATCH  $base"
  fi
done
echo "------------------------------------------------------------"
echo "in-process .bpf.c vs golden: MATCH=$pass  MISMATCH=$mism  skip(no-golden)=$skip"
[ $mism -eq 0 ]
