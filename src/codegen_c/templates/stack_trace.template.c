/* per-unit stack-trace map (16384 unique stacks * 127 frames each).
 * stack_id() returns the kernel stack id, user_stack_id() returns the
 * userspace one. Host code reads the map by stack id to get the PCs. */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 16384);
} bpf_stacks SEC(".maps");
