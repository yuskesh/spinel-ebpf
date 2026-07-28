/* === per-unit int-event channel === */
struct @UNIT@_event {
    struct spnl_event_hdr hdr;
    __s64 value;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_events SEC(".maps");
