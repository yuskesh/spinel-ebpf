# bpf_arena — arena_set / arena_get over a u64[512] arena-resident array.
@slot0 = 0
@slot1 = 0

def tc__ingress__arena_demo
  arena_set(0, 305419896)
  arena_set(1, arena_get(0) + 1)
  @slot0 = arena_get(0)
  @slot1 = arena_get(1)
  TC_ACT_OK
end
