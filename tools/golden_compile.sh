#!/bin/sh
# The golden gate, but for C that actually compiles and loads.
#
# tools/golden.rb pins the TEXT of the generated .bpf.c. It never invokes a
# compiler, so "the codegen emits broken C" is invisible to it as long as the
# broken C is stable: the golden matches the golden. Measured on 7.1.5-ebpf /
# clang 19.1.7, six committed goldens did not survive a build -- one of them
# (78_fib_lookup_kprobe) because the C codegen had lost a context gate its own
# fixture comment says must fire, so a program that should have been refused at
# compile time shipped a golden instead.
#
# This gate closes that hole by actually running the toolchain:
#
#   clang -target bpf  ->  libbpf load (tools/spnl_load_check.c)
#
# and comparing the per-golden verdict against a committed baseline.
#
#   sh tools/golden_compile.sh            # gate (exit non-zero on any change)
#   sh tools/golden_compile.sh --update   # move the baseline (REVIEW THE DIFF)
#   sh tools/golden_compile.sh 78_fib_lookup_kprobe   # one golden, verbose
#
# Run INSIDE the build container (needs clang -target bpf, libbpf and a kernel
# with BTF), cwd anywhere:
#   container exec spnlbuild sh /work/tools/golden_compile.sh
#
# WHY A BASELINE AND NOT "EVERYTHING MUST PASS" ------------------------------
# Some goldens legitimately do not load here: eBPF forbids recursion
# (03_fib_recursion), the kernel's kfunc filter refuses bpf_qdisc_init_prologue
# (54_qdisc_blackhole), the BPF ISA before v4 has no signed division
# (10_polymorphic). Demanding green would either delete honest fixtures or
# freeze the corpus to one kernel. What is worth defending is that the set of
# failures does not GROW and does not change silently -- the same append-only
# thinking as tools/record_gate.rb.
#
# WHAT IS PINNED ------------------------------------------------------------
# The baseline pins the STATUS ONLY (ok / clang_fail / verifier_reject /
# open_fail). It deliberately does NOT pin the compiler or verifier message:
# those carry clang version strings, instruction counts and register numbers
# that move with every toolchain and kernel bump, so pinning them would turn
# routine upgrades into false failures -- a gate nobody trusts gets disabled.
# The human-readable `note` column is prose for the reviewer and is NOT
# compared (same rule record_gate.rb applies to `note` / `condition`). The
# actual message of every failure goes to the run log, where it is a diagnostic
# rather than a contract.
#
# The verdict is a function of (goldens, clang, running kernel), so the
# baseline header records where it was measured. A status difference on a
# different kernel may be environmental, not a regression: the gate says so on
# failure instead of pretending otherwise.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GOLD="$ROOT/tests/golden"
BASELINE="$GOLD/compile_status.tsv"

UPDATE=0
ONLY=""
for a in "$@"; do
  case "$a" in
    --update) UPDATE=1 ;;
    -*) echo "usage: $0 [--update] [<golden-base>]" >&2; exit 2 ;;
    *) ONLY="$a" ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LOG="${SPNL_GOLDEN_COMPILE_LOG:-$TMP/run.log}"

CLANG="${CLANG:-clang}"
CC_HOST="${CC:-cc}"
command -v "$CLANG" >/dev/null 2>&1 || {
  echo "golden-compile: $CLANG not found -- run this inside the build container" >&2; exit 2; }

# vmlinux.h: generated FRESH from the running kernel's BTF rather than reusing
# $ROOT/build/vmlinux.h. That cache is written once and never refreshed (it can
# outlive a kernel bump by months), and a verifier verdict taken against another
# kernel's type layout is exactly the confusion this gate exists to remove.
# Override with SPNL_VMLINUX_H to reproduce a specific measurement.
VMLINUX="${SPNL_VMLINUX_H:-}"
if [ -z "$VMLINUX" ]; then
  command -v bpftool >/dev/null 2>&1 || {
    echo "golden-compile: bpftool not found (needed to generate vmlinux.h)" >&2; exit 2; }
  [ -r /sys/kernel/btf/vmlinux ] || {
    echo "golden-compile: /sys/kernel/btf/vmlinux missing (kernel without CONFIG_DEBUG_INFO_BTF)" >&2; exit 2; }
  VMLINUX="$TMP/vmlinux.h"
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
  VMLINUX_SRC="fresh from /sys/kernel/btf/vmlinux"
else
  VMLINUX_SRC="\$SPNL_VMLINUX_H=$VMLINUX"
fi
INCDIR="$(dirname "$VMLINUX")"

LOADCHK="$TMP/spnl_load_check"
"$CC_HOST" -O2 -o "$LOADCHK" "$ROOT/tools/spnl_load_check.c" -lbpf -lelf -lz 2>"$TMP/loadchk.err" || {
  echo "golden-compile: could not build tools/spnl_load_check.c (libbpf-dev missing?)" >&2
  cat "$TMP/loadchk.err" >&2; exit 2; }

# Production flags (bin/spinel-ebpf bpf_clang_argv). -mcpu is pinned to the same
# baseline ISA the CLI pins, so an ISA the corpus quietly started needing shows
# up here as a clang_fail instead of at a user's site. The reproducibility
# flags (-fdebug-prefix-map, -fno-ident) only normalise recorded paths and are
# omitted: they cannot change whether the code compiles or loads.
ARCH_MACRO="-D__TARGET_ARCH_x86"
case "$(uname -m)" in aarch64|arm64) ARCH_MACRO="-D__TARGET_ARCH_arm64" ;; esac
ARCH_INC=""
for d in /usr/include/*-linux-gnu; do [ -d "$d" ] && ARCH_INC="$ARCH_INC -I $d"; done
MCPU="${SPNL_BPF_MCPU:-v1}"

{
  echo "== golden compile/load gate"
  echo "== kernel: $(uname -r)   arch: $(uname -m)"
  echo "== clang:  $($CLANG --version | head -1)"
  echo "== vmlinux.h: $VMLINUX_SRC"
  echo "== flags:  -O2 -g -target bpf $ARCH_MACRO -mcpu=$MCPU$ARCH_INC -I $INCDIR -I $ROOT/include"
  echo
} > "$LOG"

NOW="$TMP/now.tsv"
: > "$NOW"
n=0
for c in "$GOLD"/*.bpf.c; do
  [ -e "$c" ] || continue
  g="$(basename "$c" .bpf.c)"
  [ -z "$ONLY" ] || [ "$ONLY" = "$g" ] || continue
  n=$((n + 1))
  o="$TMP/$g.o"
  # shellcheck disable=SC2086
  if ! $CLANG -O2 -g -target bpf $ARCH_MACRO -mcpu="$MCPU" $ARCH_INC \
        -I "$INCDIR" -I "$ROOT/include" -c "$c" -o "$o" > "$TMP/cc.log" 2>&1; then
    printf '%s\tclang_fail\n' "$g" >> "$NOW"
    { echo "---- $g  clang_fail"
      grep -E 'error|fatal' "$TMP/cc.log" | head -4 | sed 's/^/       /'
    } >> "$LOG"
    continue
  fi
  if "$LOADCHK" "$o" > "$TMP/ld.log" 2>&1; then
    printf '%s\tok\n' "$g" >> "$NOW"
    continue
  fi
  st="verifier_reject"
  grep -q '^OPEN_FAIL' "$TMP/ld.log" && st="open_fail"
  printf '%s\t%s\n' "$g" "$st" >> "$NOW"
  { echo "---- $g  $st"
    # The first line of the load log's tail is the verifier's own verdict; the
    # libbpf lines below name the program that lost.
    tail -6 "$TMP/ld.log" | sed 's/^/       /'
  } >> "$LOG"
done

# A gate that measured nothing is not a pass (same guard as tools/golden.rb).
if [ "$n" -eq 0 ]; then
  echo "golden-compile: no goldens were measured${ONLY:+ (no golden named '$ONLY')}" >&2
  exit 2
fi

sort -o "$NOW" "$NOW"

if [ "$UPDATE" -eq 1 ]; then
  [ -z "$ONLY" ] || { echo "golden-compile: --update measures the whole corpus; drop the filter" >&2; exit 2; }
  # Carry existing notes across so a refresh does not silently erase the prose
  # that explains why a known failure is known.
  #
  # This was found the hard way: reading $BASELINE from *inside* a block whose
  # stdout is redirected to $BASELINE reads an empty file, because the shell
  # truncates the target before the block runs -- so every note was silently
  # blanked. Snapshot the old notes first; the redirect can then do what it likes.
  PREV_NOTES=""
  if [ -f "$BASELINE" ]; then
    PREV_NOTES="$TMP/prev_notes.tsv"
    cp "$BASELINE" "$PREV_NOTES"
  fi
  {
    echo "# spinel-ebpf golden compile/load baseline."
    echo "#"
    echo "# Each committed tests/golden/*.bpf.c compiled with the production clang"
    echo "# flags and loaded with tools/spnl_load_check.c. Only the STATUS column is"
    echo "# compared; \`note\` is prose for the reviewer (the compiler/verifier message"
    echo "# itself is version-dependent and deliberately not pinned -- see the header"
    echo "# of tools/golden_compile.sh)."
    echo "#"
    echo "# A non-ok status is not permission to leave it broken: it is a claim that"
    echo "# somebody looked. Refresh with \`sh tools/golden_compile.sh --update\` and"
    echo "# review the diff -- a new failure means the codegen started emitting C that"
    echo "# does not build or does not load."
    echo "#"
    echo "# measured: kernel=$(uname -r) arch=$(uname -m) clang=$($CLANG --version | head -1 | sed 's/.*version //;s/ .*//') mcpu=$MCPU"
    echo "#"
    printf '# golden\tstatus\tnote\n'
    if [ -n "$PREV_NOTES" ]; then
      awk -F'\t' 'NR==FNR { if ($0 ~ /^#/ || $0 == "") next; note[$1]=$3; next }
                  { printf "%s\t%s\t%s\n", $1, $2, ($1 in note ? note[$1] : "") }' \
          "$PREV_NOTES" "$NOW"
    else
      awk -F'\t' '{ printf "%s\t%s\t\n", $1, $2 }' "$NOW"
    fi
  } > "$BASELINE"
  ok=$(awk -F'\t' '$2=="ok"' "$NOW" | wc -l | tr -d ' ')
  echo "golden-compile: wrote $(basename "$BASELINE") -- $n goldens, ok=$ok -- REVIEW THE DIFF"
  [ "$LOG" = "$TMP/run.log" ] || echo "golden-compile: log -> $LOG"
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  echo "golden-compile: $BASELINE is missing (create it with: sh tools/golden_compile.sh --update)" >&2
  exit 1
fi

awk -F'\t' -v only="$ONLY" '
  NR==FNR { if ($0 ~ /^#/ || $0 == "") next; base[$1]=$2; note[$1]=$3; next }
  { now[$1]=$2 }
  END {
    bad = 0
    for (g in now) {
      if (!(g in base)) {
        printf "  NEW         %-30s %s  (golden not in the baseline; run --update)\n", g, now[g]
        bad++
      } else if (base[g] != now[g]) {
        if (base[g] == "ok")
          printf "  REGRESSION  %-30s ok -> %s\n", g, now[g]
        else if (now[g] == "ok")
          printf "  IMPROVED    %-30s %s -> ok  (run --update to accept)\n", g, base[g]
        else
          printf "  CHANGED     %-30s %s -> %s\n", g, base[g], now[g]
        bad++
      }
    }
    if (only == "") {
      for (g in base) if (!(g in now)) {
        printf "  REMOVED     %-30s was %s  (no tests/golden/%s.bpf.c; run --update)\n", g, base[g], g
        bad++
      }
    }
    for (g in now) c[now[g]]++
    printf "------------------------------------------------------------\n"
    printf "golden compile/load: n=%d  ok=%d  clang_fail=%d  verifier_reject=%d  open_fail=%d\n",
           length(now), c["ok"]+0, c["clang_fail"]+0, c["verifier_reject"]+0, c["open_fail"]+0
    printf "changes vs baseline: %d\n", bad
    exit (bad ? 1 : 0)
  }
' "$BASELINE" "$NOW" || rc=$?
rc=${rc:-0}

if [ "$rc" -ne 0 ]; then
  echo
  echo "Details of every non-ok golden in this run:"
  sed 's/^/  /' "$LOG"
  echo
  echo "A verifier verdict depends on the kernel and a clang error on the compiler."
  echo "This run: kernel=$(uname -r) clang=$($CLANG --version | head -1 | sed 's/.*version //;s/ .*//')."
  echo "The baseline records what it was measured on:"
  grep '^# measured:' "$BASELINE" | sed 's/^/  /'
  echo "If they differ, the change may be environmental -- say so rather than assuming"
  echo "a regression. If the codegen really did change, that is the regression."
fi
exit "$rc"
