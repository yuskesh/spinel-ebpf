/* keyed log2 histogram (1024 keys * 64 slots).
 * The value struct is 512 bytes - too large to put on the BPF
 * stack (512B limit). We stash a pre-zeroed template in a per-CPU
 * ARRAY of size 1 and use it for new-key initialization. */
struct spnl_hist_struct { __u64 buckets[64]; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct spnl_hist_struct);
    __uint(max_entries, 1024);
} bpf_hist_keyed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct spnl_hist_struct);
    __uint(max_entries, 1);
} bpf_hist_keyed_zero SEC(".maps");

static __noinline __s64 spnl_hist_observe_by(__s64 key, __s64 v)
{
    __u64 k = (__u64)key;
    struct spnl_hist_struct *cur = bpf_map_lookup_elem(&bpf_hist_keyed, &k);
    if (!cur) {
        __u32 zk = 0;
        struct spnl_hist_struct *zero =
            bpf_map_lookup_elem(&bpf_hist_keyed_zero, &zk);
        if (!zero) return 0;
        bpf_map_update_elem(&bpf_hist_keyed, &k, zero, BPF_NOEXIST);
        cur = bpf_map_lookup_elem(&bpf_hist_keyed, &k);
        if (!cur) return 0;
    }
    __u32 slot = (__u32)spnl_hist_log2(v);
    if (slot >= 64) return 0;
    __sync_fetch_and_add(&cur->buckets[slot], 1);
    return 0;
}
