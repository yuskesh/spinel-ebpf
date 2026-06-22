# A real data structure in bpf_arena — an open-addressing hash table.
# arena_hash_set(key, val) / arena_hash_get(key) treat the arena array as
# 256 (key, value) buckets, indexed by a multiplicative hash of the key with
# 8-way linear probing (fully unrolled, no runtime loop). The whole table lives
# in arena memory, so userspace can mmap and read the same key/value pairs — a
# kernel/user shared hash map written in Ruby.
#
# key 0 is reserved (empty marker). Here we set two keys, update one, and read
# them back (plus an absent key) so a BPF_PROG_TEST_RUN harness can verify.
#
# Build (needs clang -mcpu=v3, added automatically when arena is used):
#   spinel-ebpf compile examples/observability/tc_arena_hash.rb -o build/ah --build
@v1 = 0
@v2 = 0
@v3 = 0

def tc__ingress__hashdemo
  arena_hash_set(1001, 42)
  arena_hash_set(2002, 99)
  arena_hash_set(1001, 50)      # update key 1001's value
  @v1 = arena_hash_get(1001)    # 50 (updated)
  @v2 = arena_hash_get(2002)    # 99
  @v3 = arena_hash_get(7777)    # 0 (absent)
  TC_ACT_OK
end

puts "tc_arena_hash loaded"
sleep 3600
