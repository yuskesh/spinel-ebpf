/* === per-unit Redis L7 RED === */
static __always_inline int spnl_is_redis_cmd(const unsigned char *h) {
    return h[0]=='*' && h[1]>='1' && h[1]<='9';
}

struct @UNIT@_redis_pending_st {
    __u64 start_ns;
    __u32 pid;
    char comm[16];
    unsigned char req[64];
    __u64 cgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct @UNIT@_redis_pending_st);
} @UNIT@_redis_pending SEC(".maps");

struct @UNIT@_redis_stash_st {
    __u64 sk;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct @UNIT@_redis_stash_st);
} @UNIT@_redis_recv_stash SEC(".maps");

