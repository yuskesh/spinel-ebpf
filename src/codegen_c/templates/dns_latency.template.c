/* === per-unit DNS request/response latency correlation === */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} @UNIT@_dns_pending SEC(".maps");

struct @UNIT@_dns_recv_stash_st {
    __u64 sk;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct @UNIT@_dns_recv_stash_st);
} @UNIT@_dns_recv_stash SEC(".maps");
