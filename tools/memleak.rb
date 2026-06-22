# memleak — track un-freed kernel allocations, grouped by allocation stack
# (bcc memleak equivalent, kernel/kmalloc mode).
#
# Every kmalloc records {ptr -> (size, kernel stack)} in bpf_allocs; every kfree
# deletes the entry. After the sample window, the surviving entries are
# allocations that were never freed — grouped by stack, sorted by bytes,
# symbolized via /proc/kallsyms (spnl_dump_leaks). Long-lived kernel objects
# show up as "outstanding"; a true leak is a stack whose bytes keep growing.
#
#   bin/spinel-ebpf compile tools/memleak.rb --build -o build/memleak
#   sudo ./build/memleak/memleak
module Leak
  ffi_func :spnl_dump_leaks, [:str, :str, :int], :int
end

def tracepoint__kmem__kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
  leak_record(ptr, bytes_alloc, stack_id)
  0
end

def tracepoint__kmem__kfree(call_site, ptr)
  leak_forget(ptr)
  0
end

puts "[memleak] tracking kmalloc/kfree for 5s..."
sleep 5
Leak.spnl_dump_leaks("bpf_allocs", "bpf_stacks", 8)
