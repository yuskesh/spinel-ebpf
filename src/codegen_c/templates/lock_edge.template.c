/* per-unit lock-order edge map for deadlock detection.
 * key = {lock_a, lock_b} (a was held when b was acquired). */
struct spnl_lock_edge {
    __u64 a;
    __u64 b;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct spnl_lock_edge);
    __type(value, __u64);
    __uint(max_entries, 65536);
} bpf_lock_edges SEC(".maps");

static __noinline __s64 spnl_lock_edge(__s64 a, __s64 b)
{
    struct spnl_lock_edge k = {};
    k.a = (__u64)a;
    k.b = (__u64)b;
    __u64 *v = bpf_map_lookup_elem(&bpf_lock_edges, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&bpf_lock_edges, &k, &one, BPF_NOEXIST);
    }
    return 0;
}
