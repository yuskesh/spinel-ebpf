/* per-unit CIDR blocklist (LPM_TRIE). Populated from userspace via
 * sp_bpf_cidr_blocklist_add(ip_host_order, prefixlen) / _del, read from
 * BPF via spnl_cidr_blocklist_match(ip_host_order). The key's data[] is
 * big-endian (network order) - the trie matches bits MSB-first. */
struct spnl_cidr_key {
    __u32 prefixlen;
    __u8  data[4];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct spnl_cidr_key);
    __type(value, __u8);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bpf_cidr_block SEC(".maps");

static __noinline __s64 spnl_cidr_blocklist_match(__s64 ip_host_order)
{
    struct spnl_cidr_key k;
    __u32 ip = (__u32)ip_host_order;
    k.prefixlen = 32;
    k.data[0] = (__u8)((ip >> 24) & 0xff);
    k.data[1] = (__u8)((ip >> 16) & 0xff);
    k.data[2] = (__u8)((ip >> 8) & 0xff);
    k.data[3] = (__u8)(ip & 0xff);
    __u8 *v = bpf_map_lookup_elem(&bpf_cidr_block, &k);
    return v ? 1 : 0;
}
