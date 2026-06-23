# divu(a, b) / comm_hash / emit_comm demo.
# Combined with the glue.c-exposed `spnl_dump_log2_hist` FFI so the binary
# self-dumps a bcc-style histogram on exit.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/comm_divu_demo.rb \
#                   -o build/comm_divu --build
# Run:
#   ./build/comm_divu/comm_divu_demo &
#   for i in $(seq 1 100); do cat /etc/hostname > /dev/null; done
#   # bpftool map dump name bpf_hist        — log2 latency
#   # bpftool map dump name bpf_hist_lin    — divu'd µs slot
#   # ringbuf has comm strings (one per openat)

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
  emit_comm
end

def kretprobe__do_sys_openat2(ret)
  d = latency_end
  hist_observe(d)                       # log2 ns hist
  hist_observe_linear(divu(d, 1000))    # linear µs hist (unsigned div)
end

puts "comm_divu_demo loaded — bpftool map dump name bpf_hist / bpf_hist_lin"
sleep 3600
