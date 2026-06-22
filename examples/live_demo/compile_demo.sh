#!/bin/sh
# Live compile demo: show Ruby -> C -> build in 3 steps.
# Usage:  sh examples/live_demo/compile_demo.sh [foo.rb]
#   With no argument, uses ws_traffic.rb (an eBPF program that observes :8080
#   sends via kprobe) as the subject.
#   Each step advances on Enter (for narrating live while presenting).
RB="${1:-examples/live_demo/ws_traffic.rb}"
OUT=/tmp/cdemo
cd /work || exit 1
base=$(basename "$RB" .rb)
rm -rf "$OUT"; mkdir -p "$OUT"
B=$(printf '\033[1m'); C=$(printf '\033[1;36m'); Y=$(printf '\033[33m')
G=$(printf '\033[32m'); D=$(printf '\033[2m'); R=$(printf '\033[0m')
rule="------------------------------------------------------------"
pause(){ printf "\n%s  [Enter to continue]%s" "$D" "$R"; read _; }

printf "%s== spinel-ebpf: write Ruby -> compile to C -> build ==%s\n" "$C" "$R"

printf "\n%s1. Ruby source%s  (%s)\n" "$B" "$R" "$RB"
printf "%s\n" "$rule"; cat "$RB"; printf "%s\n" "$rule"
pause

printf "\n%s2. Ruby -> C compile%s  (no build yet: source generation only)\n" "$B" "$R"
printf "%s\$ spinel-ebpf compile %s -o %s%s\n\n" "$Y" "$RB" "$OUT" "$R"
ruby bin/spinel-ebpf compile "$RB" -o "$OUT" 2>&1 | grep -vE '\.ir$'
printf "\n  -> two C files are emitted: %s%s.c%s (native, runs on host) and %s%s.bpf.c%s (eBPF, runs in the kernel)\n" "$C" "$base" "$R" "$C" "$base" "$R"
pause

printf "\n%s   generated eBPF C  (%s.bpf.c)%s\n" "$B" "$base" "$R"
printf "%s\n" "$rule"; cat "$OUT/$base.bpf.c"; printf "%s\n" "$rule"
printf "  ^ the Ruby method in %s became an eBPF program at %sSEC(\"kprobe/tcp_sendmsg\")%s\n" "$RB" "$C" "$R"
pause

printf "\n%s3. Build%s  (.bpf.c ->[clang -target bpf]-> eBPF bytecode .bpf.o -> skeleton -> link with native)\n" "$B" "$R"
printf "%s\$ spinel-ebpf compile %s --build -o %s%s\n\n" "$Y" "$RB" "$OUT" "$R"
ruby bin/spinel-ebpf compile "$RB" --build -o "$OUT" 2>&1 | grep -iE 'wrote|eBPF programs' | grep -vi warning
printf "\n  artifacts:\n"
ls -la "$OUT/$base" "$OUT/$base.bpf.o" 2>/dev/null | awk '{printf "   %9s  %s\n",$5,$NF}'
file "$OUT/$base" 2>/dev/null | sed 's/^/   /'
printf "\n  -> running %s%s/%s%s loads + attaches the eBPF program.\n" "$G" "$OUT" "$base" "$R"
printf "  (type a longer command in the terminal above and the sent bytes scroll below)\n"
