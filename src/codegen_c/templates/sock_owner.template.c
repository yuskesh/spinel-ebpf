/* === per-unit socket->owner correlation map === */
struct @UNIT@_sock_owner_info {
    __u32 pid;
    char comm[16];
    __u64 cgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct @UNIT@_sock_owner_info);
} @UNIT@_sock_owner SEC(".maps");
