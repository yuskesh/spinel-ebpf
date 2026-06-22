# Dynamic config injection through bpf_arena (userspace -> BPF). The BPF
# program reads a config value from arena slot 0 every packet; userspace mmaps
# the same arena and WRITES new config at runtime. Because the arena is shared
# memory, the program picks up the new value with no reload and no map-update
# syscall path — the reverse direction of a userspace read.
#
# The accompanying test harness writes 7 then 9 to slot 0 between test_runs and
# checks @scaled tracks it (70 then 90).
@got    = 0
@scaled = 0

def tc__ingress__cfg
  c = arena_get(0)     # config injected by userspace via mmap
  @got    = c
  @scaled = c * 10
  TC_ACT_OK
end

puts "tc_arena_config loaded"
sleep 3600
