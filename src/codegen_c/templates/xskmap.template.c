/* XSKMAP for AF_XDP zero-copy redirect to user sockets. */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} bpf_xskmap SEC(".maps");
