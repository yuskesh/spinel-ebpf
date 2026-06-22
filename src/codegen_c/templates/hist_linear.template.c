/* linear histogram (256 caller-bucketed slots). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} bpf_hist_lin SEC(".maps");

static __noinline __s64 spnl_hist_observe_linear(__s64 slot_arg)
{
    if (slot_arg < 0) return 0;
    __u32 slot = (__u32)slot_arg;
    if (slot >= 256) slot = 255;
    __u64 *cur = bpf_map_lookup_elem(&bpf_hist_lin, &slot);
    if (cur) __sync_fetch_and_add(cur, 1);
    return 0;
}
