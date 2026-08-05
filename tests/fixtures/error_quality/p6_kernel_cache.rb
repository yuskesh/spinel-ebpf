# `kernel_cache` -- a top-level directive the production codegen never
# implemented. It parsed, partitioning announced an eBPF method, and the emitted
# .bpf.c had zero programs; the build succeeded and nothing was ever served.
module KCache
  ffi_func :sp_kc_set, [:str, :str], :int
end

def kernel_cache(path, body)
  KCache.sp_kc_set(path, body)
end

kernel_cache "/ping", "PONG\n"
