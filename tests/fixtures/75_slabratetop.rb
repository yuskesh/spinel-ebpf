# slab allocation rate + size (bcc slabratetop). kmem_cache_alloc's
# bytes_alloc (object size) is binned into a log2 histogram.
@allocs = 0

def tracepoint__kmem__kmem_cache_alloc(bytes_alloc)
  @allocs += 1
  hist_observe(bytes_alloc)
  0
end
