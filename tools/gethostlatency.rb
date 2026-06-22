# gethostlatency — latency of name resolution (bcc gethostlatency equivalent).
#
# uprobe/uretprobe getaddrinfo in libc, timed with the tid-keyed latency helper
# (entry stamps, return computes the delta), binned into a log2 histogram. Set
# SPNL_UPROBE_BINARY to libc so the symbol resolves.
#
#   export SPNL_UPROBE_BINARY=/lib/aarch64-linux-gnu/libc.so.6
#   bin/spinel-ebpf compile tools/gethostlatency.rb --build -o build/gethostlatency
#   sudo -E ./build/gethostlatency/gethostlatency   # samples 5s, then histogram
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def uprobe__getaddrinfo
  latency_start
  0
end

def uretprobe__getaddrinfo(ret)
  hist_observe(latency_end)
  0
end

puts "[gethostlatency] measuring getaddrinfo latency for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "getaddrinfo latency (ns)")
