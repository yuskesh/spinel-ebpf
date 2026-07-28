#!/usr/bin/env bash
#
# run_amp_check.sh -- positive and negative controls for the amp-m7
# pre-distribution bytecode checker.
#
# positive: the probes the amp codegen emits (blink/heartbeat/phc) pass the checker.
# negative: a probe carrying a Linux helper (a bpf_* call the amp preamble does not
#           provide) and bytecode with a backward branch (a loop) are both REJECTED.
# Together these show that "the M7 runs arbitrary unverified bytecode" is ruled out
# before anything is distributed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
SPINEL_DIR="${SPINEL_DIR:-$REPO_ROOT/deps/spinel}"
ICC="$REPO_ROOT/build/codegen_c/spinel-ebpf-cc"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

echo "[amp-check] building amp_check"
"$CC" -O2 -Wall -Wextra -Werror -I "$REPO_ROOT/include" src/runtime/amp/amp_check.c -o "$TMP/amp_check"

amp_bpf() {   # $1 = ruby probe -> $2 = .bpf.o
  SPNL_AMP_M7=1 "$ICC" "$1" amp 2>/dev/null > "$TMP/p.bpf.c"
  clang -O2 -target bpf -c "$TMP/p.bpf.c" -o "$2"
}

echo "[amp-check] POSITIVE: amp probes must pass the checker"
for rb in examples/observability/amp/blink.rb examples/observability/amp/heartbeat.rb examples/observability/amp/phc_delta.rb; do
  amp_bpf "$rb" "$TMP/ok.bpf.o"
  if "$TMP/amp_check" "$TMP/ok.bpf.o" 2>"$TMP/e"; then echo "  ok: $(basename "$rb")"; else echo "  FAIL(rejected): $rb -> $(cat "$TMP/e")"; fail=1; fi
done

echo "[amp-check] NEGATIVE 1: disallowed helper id (a bpf_* the amp runtime never provides) must be REJECTED"
# A hand-crafted probe that calls helper id 6 (not in the amp allowlist {1,2}).
cat > "$TMP/bad.c" <<'C'
static unsigned long long (*bad_helper)(unsigned long long) = (void *)6;
int f(void *ctx){ (void)ctx; return (int)bad_helper(0); }
C
clang -O2 -target bpf -c "$TMP/bad.c" -o "$TMP/bad.bpf.o"
if "$TMP/amp_check" "$TMP/bad.bpf.o" 2>"$TMP/e"; then echo "  FAIL(passed a disallowed-helper prog): $(cat "$TMP/e")"; fail=1
else echo "  ok: rejected -> $(grep -o 'disallowed helper[^)]*)' "$TMP/e" || cat "$TMP/e")"; fi

echo "[amp-check] NEGATIVE 2: back-edge (loop) bytecode must be REJECTED"
cat > "$TMP/loop.c" <<'C'
int f(void *ctx){ (void)ctx; volatile int i=0; int s=0; while(i<10){ s+=i; i++; } return s; }
C
clang -O2 -target bpf -c "$TMP/loop.c" -o "$TMP/loop.bpf.o"
if "$TMP/amp_check" "$TMP/loop.bpf.o" 2>"$TMP/e"; then echo "  FAIL(passed a looping prog): $(cat "$TMP/e")"; fail=1
else echo "  ok: rejected -> $(grep -o 'backward branch[^)]*)' "$TMP/e" || cat "$TMP/e")"; fi

echo "[amp-check] NEGATIVE 3: out-of-ABI memory store must be REJECTED (range check)"
# A hand-crafted probe that writes to a fixed address OUTSIDE the ivar carveout
# (0x20000000 = DTCM base, not in [AMP_IVARS_BASE, +AMP_IVARS_SIZE)). A malicious
# blob "writes to memory via a different immediate" -- the range check must catch it.
cat > "$TMP/oob.c" <<'C'
int f(void *ctx){ (void)ctx; *(volatile unsigned int *)0x20000000u = 5u; return 0; }
C
clang -O2 -target bpf -c "$TMP/oob.c" -o "$TMP/oob.bpf.o"
if "$TMP/amp_check" "$TMP/oob.bpf.o" 2>"$TMP/e"; then echo "  FAIL(passed an out-of-ABI store): $(cat "$TMP/e")"; fail=1
else echo "  ok: rejected -> $(grep -o 'outside the fixed ABI[^)]*)' "$TMP/e" || cat "$TMP/e")"; fi

echo "[amp-check] NEGATIVE 4: store to the shared ring (0x88400000) must be REJECTED"
# The M7 must never let a probe scribble the A55-facing ring directly (LDDW path,
# bit31 set). spnl_emit goes through the amp_emit helper, never a raw ring write.
cat > "$TMP/ring.c" <<'C'
int f(void *ctx){ (void)ctx; *(volatile unsigned int *)0x88400000ull = 7u; return 0; }
C
clang -O2 -target bpf -c "$TMP/ring.c" -o "$TMP/ring.bpf.o"
if "$TMP/amp_check" "$TMP/ring.bpf.o" 2>"$TMP/e"; then echo "  FAIL(passed a ring-write prog): $(cat "$TMP/e")"; fail=1
else echo "  ok: rejected -> $(grep -o 'outside the fixed ABI[^)]*)' "$TMP/e" || cat "$TMP/e")"; fi

if [ "$fail" -eq 0 ]; then echo "PASS: amp-m7 pre-distribution checker (positive + negative controls)"; else echo "FAIL"; exit 1; fi
