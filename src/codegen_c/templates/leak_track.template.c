/* per-unit outstanding-allocation map for memleak-style tools.
 * key = allocation pointer, value = {size, stack_id}. Host reads the
 * surviving entries (= un-freed allocations) and groups by stack_id. */
struct spnl_alloc_info {
    __s64 size;
    __s64 stack_id;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct spnl_alloc_info);
    __uint(max_entries, 262144);
} bpf_allocs SEC(".maps");

static __noinline __s64 spnl_leak_record(__s64 ptr, __s64 size, __s64 stack_id)
{
    __u64 k = (__u64)ptr;
    struct spnl_alloc_info info = {};
    info.size = size;
    info.stack_id = stack_id;
    bpf_map_update_elem(&bpf_allocs, &k, &info, BPF_ANY);
    return 0;
}

static __noinline __s64 spnl_leak_forget(__s64 ptr)
{
    __u64 k = (__u64)ptr;
    bpf_map_delete_elem(&bpf_allocs, &k);
    return 0;
}
