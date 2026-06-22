# slabratetop — slab object allocation rate + size distribution (bcc slabratetop).
#
# kmem:kmem_cache_alloc fires per slab object allocation. We count the rate
# (@allocs) and bin the object size (bytes_alloc) into a log2 histogram, showing
# which slab sizes dominate. (The per-cache name is a __data_loc string, omitted
# here — sizes already separate the common caches: 64/128/256/512/... byte.)
#
#   bin/spinel-ebpf compile tools/slabratetop.rb --build -o build/slabratetop
#   sudo ./build/slabratetop/slabratetop
@allocs = 0

module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def tracepoint__kmem__kmem_cache_alloc(bytes_alloc)
  @allocs += 1
  hist_observe(bytes_alloc)
  0
end

puts "[slabratetop] counting slab allocations for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "kmem_cache_alloc object size (bytes)")
