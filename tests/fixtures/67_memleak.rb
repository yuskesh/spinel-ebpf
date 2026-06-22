# kernel allocation tracking (bcc memleak). kmalloc records the
# outstanding allocation keyed by its pointer + kernel stack; kfree forgets it.
# Surviving entries at report time are allocations that were never freed.
def tracepoint__kmem__kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
  leak_record(ptr, bytes_alloc, stack_id)
  0
end

def tracepoint__kmem__kfree(call_site, ptr)
  leak_forget(ptr)
  0
end
