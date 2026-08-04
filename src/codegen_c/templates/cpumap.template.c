/* CPUMAP for XDP per-CPU fanout. Entries are populated from
 * userspace (e.g. via bpftool map update or libbpf). Value is a
 * 64-bit `bpf_cpumap_val { __u32 qsize; __u32 prog_id; }` -- userspace
 * supplies a `qsize` (typically 192) and optionally a secondary
 * XDP prog id to run on the destination CPU. */
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_cpumap_val));
    __uint(max_entries, 64);
} spnl_cpumap SEC(".maps");
