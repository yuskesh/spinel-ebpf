/* === per-unit connect-event channel === */
struct @UNIT@_conn_event {
    struct spnl_event_hdr hdr;
    __u32 pid;
    char comm[16];
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __s64 srtt_us;
    __u64 cgid;
    __u32 oldstate;
    __u64 daddr6_hi;
    __u64 daddr6_lo;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_conn_events SEC(".maps");
