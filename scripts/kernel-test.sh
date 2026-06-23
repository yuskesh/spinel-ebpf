#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Kernel load-check harness (tier 2): compile representative Ruby programs to
# eBPF, then load + verify them in a *running* eBPF-capable kernel.
#
# The GitHub CI (tier 1) stops at codegen because hosted runners can't boot the
# custom kernel. This script is the next gate: run it on a host -- or inside an
# Apple container -- booted on an eBPF-capable kernel to prove the generated
# .bpf.c is accepted by the in-kernel verifier across the main program types:
#
#   XDP            network datapath          (tests/kernel/xdp_counter.rb)
#   kprobe         tracing                   (tests/kernel/kprobe_counter.rb)
#   TC ingress     packet-header accessors   (tests/kernel/tc_classifier.rb)
#   struct_ops     kernel struct injection   (tests/kernel/tcp_cc.rb)
#
# Requirements on the target host:
#   - an eBPF-capable kernel with BTF (/sys/kernel/btf/vmlinux)
#   - clang (bpf target) and bpftool
#   - the spinel compiler built into deps/spinel (run scripts/setup.sh first)
#   - root (to mount bpffs and load programs)
#
# Usage:
#   sudo scripts/kernel-test.sh
#
# Exit status: 0 if every program loads, non-zero otherwise.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

WORK="${WORK:-$(mktemp -d)}"
PINBASE=/sys/fs/bpf/spnl_kt

# 1. Preconditions ----------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "!!! missing required tool: $1"; exit 1; }; }
need clang
need bpftool
[ "$(id -u)" = 0 ]                 || { echo "!!! must run as root (mounts bpffs + loads programs)"; exit 1; }
[ -r /sys/kernel/btf/vmlinux ]    || { echo "!!! no kernel BTF (/sys/kernel/btf/vmlinux); need CONFIG_DEBUG_INFO_BTF=y"; exit 1; }
[ -x bin/spinel-ebpf ]            || { echo "!!! bin/spinel-ebpf not found (run from the repo, or chmod +x)"; exit 1; }
[ -x deps/spinel/bin/spinel ]     || { echo "!!! deps/spinel not built -- run scripts/setup.sh first"; exit 1; }

# Same BPF target arch macro the production build uses (see bin/spinel-ebpf).
case "$(uname -m)" in
  aarch64|arm64) ARCH=-D__TARGET_ARCH_arm64 ;;
  x86_64)        ARCH=-D__TARGET_ARCH_x86   ;;
  *) echo "!!! unsupported arch: $(uname -m)"; exit 1 ;;
esac

# 2. bpffs, for pinning loaded programs -------------------------------------
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
rm -rf "$PINBASE"; mkdir -p "$PINBASE"
trap 'rm -rf "$PINBASE"' EXIT

# 3. vmlinux.h from the running kernel's own BTF ----------------------------
echo ">>> generating vmlinux.h from running kernel BTF ($(uname -r))"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$WORK/vmlinux.h"
[ -s "$WORK/vmlinux.h" ] || { echo "!!! vmlinux.h generation failed"; exit 1; }

# 4. Load-check each representative program ---------------------------------
# compile (.rb -> .bpf.c via in-process codegen) -> clang (.bpf.c -> .bpf.o)
# -> bpftool prog loadall (runs the in-kernel verifier).
PROGRAMS="xdp_counter kprobe_counter tc_classifier tcp_cc"
pass=0; fail=0
for prog in $PROGRAMS; do
  src="tests/kernel/$prog.rb"
  d="$WORK/$prog"; mkdir -p "$d"; cp "$WORK/vmlinux.h" "$d/vmlinux.h"
  printf '%-16s ' "$prog"

  if ! ./bin/spinel-ebpf compile "$src" -o "$d" >"$d/compile.log" 2>&1; then
    echo "FAIL (codegen)"; tail -3 "$d/compile.log" | sed 's/^/    /'; fail=$((fail+1)); continue
  fi
  bpf_c="$d/$prog.bpf.c"
  [ -s "$bpf_c" ] || { echo "FAIL (no .bpf.c emitted)"; fail=$((fail+1)); continue; }

  # bpf_arena programs need ISA v3 for the address-space cast (matches bin/spinel-ebpf).
  cpu=""
  if grep -q "address_space(1)" "$bpf_c"; then cpu="-mcpu=v3"; fi
  if ! clang -O2 -g -target bpf "$ARCH" $cpu -I "$d" -I include -c "$bpf_c" -o "$d/$prog.bpf.o" 2>"$d/clang.log"; then
    echo "FAIL (clang)"; grep -i error "$d/clang.log" | head -2 | sed 's/^/    /'; fail=$((fail+1)); continue
  fi

  pin="$PINBASE/$prog"; rm -rf "$pin"
  if bpftool prog loadall "$d/$prog.bpf.o" "$pin" >"$d/load.log" 2>&1; then
    n=$(ls "$pin" 2>/dev/null | wc -l | tr -d ' ')
    echo "OK (verifier accepted, $n prog(s))"; pass=$((pass+1))
  else
    echo "FAIL (verifier)"; tail -4 "$d/load.log" | sed 's/^/    /'; fail=$((fail+1))
  fi
  rm -rf "$pin"
done

echo
echo ">>> kernel load-check: $pass passed, $fail failed   (kernel $(uname -r))"
[ "$fail" = 0 ]
