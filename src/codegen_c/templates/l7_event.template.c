/* === per-unit L7 latency-event channel === */
struct @UNIT@_l7_event {
    struct spnl_event_hdr hdr;
    __u32 pid;
    char comm[16];
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __u64 start_ktime;
    __u64 duration_ns;
    __u64 cgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_l7_events SEC(".maps");
