# Phase 2: multi-route auto kernel-cache. Declare several routes; spinel-ebpf
# synthesizes ONE pure-XDP TCP slice that dispatches each request path to its
# cache slot and serves it from the kernel. No hand-written eBPF.
#
#   spinel-ebpf compile examples/http_server/kernel_cache_demo/routes.rb --build -o build/kc
#   SPNL_XDP_IFACE=lo ./build/kc/routes &
#   curl http://127.0.0.1:8080/ping      # -> PONG
#   curl http://127.0.0.1:8080/health    # -> OK
#   curl http://127.0.0.1:8080/version   # -> (runtime-built string)
#   curl http://127.0.0.1:8080/nope      # -> no declared route -> dropped

module KCache
  ffi_func :sp_kc_set, [:str, :str], :int
end

# kernel_cache "<path>", <body>: compile time => the path becomes an XDP match
# slot; runtime => the body is pushed into that slot's kernel cache.
def kernel_cache(path, body)
  KCache.sp_kc_set(path, body)
end

kernel_cache "/ping",   "PONG\n"
kernel_cache "/health", "OK\n"
ver = "spinel-ebpf " + "kernel-cache v2\n"   # runtime-built body
kernel_cache "/version", ver

puts "[kc] /ping /health /version served from the kernel (pure-XDP, multi-route)."
puts "[kc] sleeping 120s so XDP stays attached"
sleep 120
