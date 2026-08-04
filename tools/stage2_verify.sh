#!/bin/sh
# In-process codegen gate. Run INSIDE the build
# container (spnlbuild), cwd = repo root. Confirms the PRODUCTION in-process
# codegen (parse+analyze .rb -> Compiler -> emit, no --emit-ir) reproduces the
# committed goldens (tests/golden/*.bpf.c) byte-for-byte — the same goldens the
# host gate (tools/golden.rb) pins the text codegen to. Together: golden.rb gates
# the codegen logic on the host; this gates that the in-process path == golden.
#
# (This used to diff the in-process output against the Ruby CodegenBpf oracle;
#  that lockstep is retired -- the goldens are the source of truth now. See
#  tools/golden.rb / tools/cgen_oracle.rb.)
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

# The refusals have to hold on THIS path too. A fixture with no golden is
# skipped above, so a context gate that stopped firing in the in-process build
# would look exactly like a fixture that has no eBPF content. tools/golden.rb
# pins the same set for the text driver; both drivers compile the same TU, and
# this is the half a user's `spinel-ebpf compile` actually runs.
REJ=tests/golden/codegen_reject.tsv
rej_bad=0
if [ -f "$REJ" ]; then
  rej_n=0
  while IFS="$(printf '\t')" read -r base _note; do
    case "$base" in ''|'#'*) continue ;; esac
    [ -f "tests/fixtures/$base.rb" ] || { echo "REJECT-LIST  $base has no fixture"; rej_bad=$((rej_bad + 1)); continue; }
    rej_n=$((rej_n + 1))
    if build/codegen_c/spinel-ebpf-cc "tests/fixtures/$base.rb" "$base" >/dev/null 2>&1; then
      echo "NOT REFUSED  $base  (the in-process codegen accepted a fixture the text driver refuses)"
      rej_bad=$((rej_bad + 1))
    fi
  done < "$REJ"
  echo "in-process refusals vs $REJ: CHECKED=$rej_n  UNEXPECTEDLY_ACCEPTED=$rej_bad"
else
  echo "in-process refusals: $REJ missing (run: ruby tools/golden.rb --update)"
  rej_bad=1
fi

[ $mism -eq 0 ] && [ $rej_bad -eq 0 ]
