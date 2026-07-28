/* === per-unit sock-keyed L7 stream channel === */
struct @UNIT@_l7stream_event {
    struct spnl_event_hdr hdr;
    __u64 sock;
    __u32 len;
    char raw[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_l7stream_events SEC(".maps");
