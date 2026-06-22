# arena hash table CRUD — set/get/del (tombstone).
@before = 0
@after  = 0

def tc__ingress__hashdemo
  arena_hash_set(1001, 42)
  arena_hash_set(2002, 99)
  arena_hash_set(3003, 7)
  @before = arena_hash_get(2002)
  arena_hash_del(2002)
  @after  = arena_hash_get(2002)
  TC_ACT_OK
end
