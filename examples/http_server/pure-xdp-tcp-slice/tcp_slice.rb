# examples/http_server/pure-xdp-tcp-slice/tcp_slice.rb
#
# The final form: a pure-XDP TCP slice for /health.
#
# Architecture: the kernel TCP stack does NOT listen on port 8080. Instead the
# XDP program intercepts SYN/data/FIN at the lo ingress hook and answers
# entirely from the eBPF side using `bpf_tcp_raw_gen_syncookie_ipv4` for
# handshake and a per-flow state map for ESTABLISHED/RESPONSE_SENT/CLOSED
# transitions. A worker process is not required: there is no `accept` queue,
# no `read`, no `write`, no `close` syscall on the server side.
#
# This is "the response does not traverse userspace" in its strongest possible
# sense -- userspace is not merely bypassed on the data path, it holds no socket
# for this port at all.
#
# Build:
#   spinel-ebpf compile examples/http_server/pure-xdp-tcp-slice/tcp_slice.rb \
#       -o build/tcp_slice --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/tcp_slice/tcp_slice
#   curl http://127.0.0.1:8080/health
#   # => 200 OK with body "OK"

# The body is a marker. The codegen recognises `xdp__tcp_slice__<name>` and
# emits the complete TCP slice machinery (bpf_conntab map + 4 helpers + the
# state-machine entry point) automatically -- the body below is *replaced* at
# compile time, not lowered.
#
# This slice is hardcoded for /health on port 8080. Making it configurable from
# the Ruby DSL (`def xdp__tcp_slice__<name>(port, prefix, body)`) is future work.
#
# There used to be a purely declarative form here as well -- `kernel_cache
# "/ping", body`, one line and no attach method at all. It was never implemented
# by the production code generator: the declaration parsed, the partitioner
# announced an eBPF method for it, and the generator then emitted a .bpf.c with
# no programs in it. The build succeeded, the binary printed "BPF loaded and
# attached", and nothing was ever served. The compiler now refuses the directive
# by name rather than leaving that shape reachable.
def xdp__tcp_slice__health
  XDP_PASS  # placeholder (codegen replaces the whole function)
end

puts "[tcp_slice] kernel-side /health responder ready"
puts "[tcp_slice] worker process not required -- strace this process should show 0 data-plane syscalls"
sleep 3600
