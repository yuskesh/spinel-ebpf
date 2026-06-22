# Full CRUD over the arena hash table + a userspace mmap reader.
# arena_hash_del(key) marks a slot as a tombstone (~0); get/set skip tombstones,
# so probe chains stay intact. The whole table lives in arena memory, so the
# accompanying harness mmaps the arena and reads the SAME (key, value) pairs
# directly — no map-lookup syscall — proving the kernel/user shared-memory
# nature of bpf_arena.
#
# Build: spinel-ebpf compile examples/observability/tc_arena_hash_crud.rb -o build/ah --build
@before = 0
@after  = 0

def tc__ingress__hashdemo
  arena_hash_set(1001, 42)
  arena_hash_set(2002, 99)
  arena_hash_set(3003, 7)
  @before = arena_hash_get(2002)   # 99 (present)
  arena_hash_del(2002)             # delete key 2002
  @after  = arena_hash_get(2002)   # 0 (gone)
  TC_ACT_OK
end

puts "tc_arena_hash_crud loaded"
sleep 3600
