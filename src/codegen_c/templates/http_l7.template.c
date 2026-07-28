struct @UNIT@_http_pending_st {
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
    __type(value, struct @UNIT@_http_pending_st);
} @UNIT@_http_pending SEC(".maps");

struct @UNIT@_http_stash_st {
    __u64 sk;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct @UNIT@_http_stash_st);
} @UNIT@_http_recv_stash SEC(".maps");

