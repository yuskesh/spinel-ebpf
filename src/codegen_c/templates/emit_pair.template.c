/* === per-unit pair-event channel === */
struct @UNIT@_pair_event {
    struct spnl_event_hdr hdr;
    __s64 a;
    __s64 b;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_pair_events SEC(".maps");
