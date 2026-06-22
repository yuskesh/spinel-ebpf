/* DEVMAP for XDP redirect to another net device (ifindex). */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} bpf_devmap SEC(".maps");
