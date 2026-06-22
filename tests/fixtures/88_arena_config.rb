# arena dynamic config — BPF reads config from arena slot 0 (written by
# userspace via mmap). Demonstrates userspace -> arena -> BPF.
@got    = 0
@scaled = 0

def tc__ingress__cfg
  c = arena_get(0)
  @got    = c
  @scaled = c * 10
  TC_ACT_OK
end
