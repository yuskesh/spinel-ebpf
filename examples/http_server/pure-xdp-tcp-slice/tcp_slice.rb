# examples/http_server/pure-xdp-tcp-slice/tcp_slice.rb
#
# Pure-XDP TCP slice for /health.
#
# Architecture: kernel TCP stack does NOT listen on port 8080. Instead the
# XDP program intercepts SYN/data/FIN at the lo ingress hook and answers
# entirely from the eBPF side using `bpf_tcp_raw_gen_syncookie_ipv4` for
# handshake and a per-flow state map for ESTABLISHED/RESPONSE_SENT/CLOSED
# transitions. Worker process is not required: there is no `accept` queue,
# no `read`, no `write`, no `close` syscall on the server side.
#
# This is the strict form of "the response does not traverse userspace" in
# its strongest possible sense.
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
# state-machine entry point) automatically — the body below is *replaced* at
# compile time, not lowered.
#
# The slice is hardcoded for /health on port 8080. A future revision will lift
# this into Ruby-DSL-configurable form (`def xdp__tcp_slice__<name>(port,
# prefix, body)`).
def xdp__tcp_slice__health
  XDP_PASS  # placeholder (codegen replaces the whole function)
end

puts "[tcp_slice] kernel-side /health responder ready"
puts "[tcp_slice] worker process not required — strace this process should show 0 data-plane syscalls"
sleep 3600
