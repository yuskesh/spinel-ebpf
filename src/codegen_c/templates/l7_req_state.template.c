/* === per-unit L7 send->recv correlation === */
struct @UNIT@_req_state {
    __u64 start_ns;
    __u32 pid;
    char comm[16];
    __u64 cgid;
    __u32 outstanding;
    __u32 mux;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct @UNIT@_req_state);
} @UNIT@_req_start SEC(".maps");
