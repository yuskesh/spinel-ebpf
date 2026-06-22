# bpf_arena from Ruby. arena_set/arena_get read and write u64 slots in a
# sparse, mmap-able shared-memory region (BPF_MAP_TYPE_ARENA). Unlike a HASH/
# ARRAY map, the slots live in the arena address space and are accessed by plain
# pointer dereference (no map helper) — and userspace can mmap the same bytes.
#
# Here we store a value, do arithmetic on it through the arena, and mirror the
# results into ivars (HASH maps) so a BPF_PROG_TEST_RUN harness can read them.
#
# Build (needs clang -mcpu=v3, added automatically when arena is used):
#   spinel-ebpf compile examples/observability/tc_arena_demo.rb -o build/arena --build
@slot0 = 0
@slot1 = 0

def tc__ingress__arena_demo
  arena_set(0, 305419896)            # 0x12345678 into arena slot 0
  arena_set(1, arena_get(0) + 1)     # slot1 = slot0 + 1, all through the arena
  @slot0 = arena_get(0)              # mirror back out for verification
  @slot1 = arena_get(1)
  TC_ACT_OK
end

puts "tc_arena_demo loaded"
sleep 3600
