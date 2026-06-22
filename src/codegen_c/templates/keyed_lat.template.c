/* per-unit arbitrary-key latency map (bcc biolatency / runqlat).
 * key = any u64 id; value = entry ktime. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 65536);
} bpf_keyed_lat SEC(".maps");

static __noinline __s64 spnl_lat_start_key(__s64 key)
{
    __u64 k = (__u64)key;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&bpf_keyed_lat, &k, &now, BPF_ANY);
    return 0;
}

static __noinline __s64 spnl_lat_end_key(__s64 key)
{
    __u64 k = (__u64)key;
    __u64 *t = bpf_map_lookup_elem(&bpf_keyed_lat, &k);
    if (!t) return 0;
    __u64 d = bpf_ktime_get_ns() - *t;
    bpf_map_delete_elem(&bpf_keyed_lat, &k);
    return (__s64)d;
}
