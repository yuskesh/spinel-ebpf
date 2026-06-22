# arena hash table — arena_hash_set/arena_hash_get (open addressing over
# the arena array). set + update + get + absent.
@v1 = 0
@v2 = 0
@v3 = 0

def tc__ingress__hashdemo
  arena_hash_set(1001, 42)
  arena_hash_set(2002, 99)
  arena_hash_set(1001, 50)
  @v1 = arena_hash_get(1001)
  @v2 = arena_hash_get(2002)
  @v3 = arena_hash_get(7777)
  TC_ACT_OK
end
