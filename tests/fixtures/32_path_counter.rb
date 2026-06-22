# Per-path L7 counter via transparent dispatch.
#
# `record_path_hit` is a top-level method that calls the BPF builtin
# `path_counter_inc`. Partition tags it :ebpf (int param, int return,
# no native-only constructs). With `spinel-ebpf compile --ebpf-dispatch`,
# the main-side call goes through bpf_prog_test_run() into the BPF program,
# which atomically updates `bpf_path_counts[key]`.
#
# Demo:
#   main simulates 5 requests with 3 distinct path keys -> map ends at
#   { 1: 3, 2: 1, 3: 1 } readable via `bpftool map dump name bpf_path_counts`.

KEY_ROOT   = 1
KEY_HEALTH = 2
KEY_OTHER  = 3

def record_path_hit(key)
  path_counter_inc(key)
  0
end

# Simulate 5 requests: 3× /, 1× /health, 1× /missing
record_path_hit(KEY_ROOT)
record_path_hit(KEY_HEALTH)
record_path_hit(KEY_ROOT)
record_path_hit(KEY_OTHER)
record_path_hit(KEY_ROOT)

puts "[demo] 5 records dispatched; bpf_path_counts should now be {1:3, 2:1, 3:1}"
puts "[demo] sleep 5s so bpftool can poke at the map before destructor releases it"
sleep 5
