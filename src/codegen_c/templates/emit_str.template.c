/* === per-unit string-event channel === */
struct @UNIT@_str_event {
    struct spnl_event_hdr hdr;
    char str[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} @UNIT@_str_events SEC(".maps");
