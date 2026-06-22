# A singly-linked list living in bpf_arena — a pointer-based data structure
# (here index-based references) over arena memory, beyond the flat array
# and hash table. arena_list_push(value) prepends a node; the list is
# stored as (value, next-index) pairs with a head index + bump allocator in the
# first two arena slots. arena_list_sum() walks the chain (bounded, unrolled) and
# totals the values. The whole list is mmap-able by userspace like any arena data.
#
# Build: spinel-ebpf compile examples/observability/tc_arena_list.rb -o build/al --build
@sum = 0

def tc__ingress__listdemo
  arena_list_push(10)
  arena_list_push(20)
  arena_list_push(30)
  @sum = arena_list_sum()    # 10 + 20 + 30 = 60
  TC_ACT_OK
end

puts "tc_arena_list loaded"
sleep 3600
