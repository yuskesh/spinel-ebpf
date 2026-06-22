/* per-unit blocklist. Populated from userspace via
 * sp_bpf_blocklist_add(uint32_t) / sp_bpf_blocklist_del(uint32_t),
 * read from BPF via spnl_blocklist_match(ip_host_order). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 8192);
} bpf_blocklist SEC(".maps");

static __noinline __s64 spnl_blocklist_match(__s64 ip_host_order)
{
    __u32 k = (__u32)ip_host_order;
    __u8 *v = bpf_map_lookup_elem(&bpf_blocklist, &k);
    return v ? 1 : 0;
}
