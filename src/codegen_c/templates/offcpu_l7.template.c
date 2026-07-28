struct @UNIT@_offcpu_stash_st {
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct @UNIT@_offcpu_stash_st);
} @UNIT@_offcpu_stash SEC(".maps");

struct @UNIT@_offcpu_win {
    __u64 start_ns;
    __u64 offcpu_ns;
    __u64 sleep_ts;
    __s32 wait_stack;
    unsigned char req[64];
    unsigned char hdr_ext[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct @UNIT@_offcpu_win);
} @UNIT@_offcpu_win SEC(".maps");

