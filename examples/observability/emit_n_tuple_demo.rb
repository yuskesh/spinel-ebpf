# spnl_emit3 / spnl_emit4 demo.
#
# Two kprobes that fan out a fixed-arity tuple per call:
#   do_sys_openat2  -> emit3(dfd, pid_high32, pid_low32)
#   tcp_v4_connect  -> emit4(sk_low32, sport, dport, daddr)
#
# Both share the same compilation unit so the host runtime sees:
#   <unit>_emit3_events    ringbuf for 3-tuples
#   <unit>_emit4_events    ringbuf for 4-tuples
#
# Build:
#   bin/spinel-ebpf compile examples/observability/emit_n_tuple_demo.rb \
#                   -o build/emit_n_tuple --build
# Run:
#   ./build/emit_n_tuple/emit_n_tuple_demo &
#   touch /tmp/probe_target   # fires do_sys_openat2 kprobe
#   curl -s http://127.0.0.1:80  # fires tcp_v4_connect kprobe
#
# Inspect the ringbufs with bpftool:
#   bpftool map dump name emit_n_tuple_demo_emit3_events
#   bpftool map dump name emit_n_tuple_demo_emit4_events

def kprobe__do_sys_openat2(dfd, filename, how)
  spnl_emit3(dfd, 0, 0)
end

def kprobe__tcp_v4_connect(sk, uaddr, addr_len)
  spnl_emit4(sk, 0, 0, 0)
end

puts "emit_n_tuple_demo loaded — exercise with file open or TCP connect"
sleep 3600
