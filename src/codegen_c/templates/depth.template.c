/* per-(tid,method) recursion depth for --instrument depth-collapse.
 * key = any u64 id (the agent uses (tid<<8)|method_idx); value = current depth.
 * depth_inc returns the depth AFTER incrementing (1 == outermost entry);
 * depth_dec returns the depth AFTER decrementing (0 == outermost exit, key freed).
 * Same-thread recursion runs on one CPU at a time, so the read-modify-write is
 * race-free for these per-thread keys. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __s64);
    __uint(max_entries, 65536);
} bpf_depth SEC(".maps");

static __noinline __s64 spnl_depth_inc(__s64 key)
{
    __u64 k = (__u64)key;
    __s64 *d = bpf_map_lookup_elem(&bpf_depth, &k);
    if (d) { *d += 1; return *d; }
    __s64 one = 1;
    bpf_map_update_elem(&bpf_depth, &k, &one, BPF_ANY);
    return 1;
}

static __noinline __s64 spnl_depth_dec(__s64 key)
{
    __u64 k = (__u64)key;
    __s64 *d = bpf_map_lookup_elem(&bpf_depth, &k);
    if (!d) return 0;
    *d -= 1;
    __s64 nv = *d;
    if (nv <= 0) bpf_map_delete_elem(&bpf_depth, &k);
    return nv;
}
