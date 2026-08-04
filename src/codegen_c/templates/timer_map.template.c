/* bpf_timer-backed periodic callback. Single ARRAY slot
 * holding the timer struct. The arm prog (also emitted) is fired
 * once by userspace at load time via bpf_prog_test_run.
 * Interval: @NS@ ns (compile-time constant). */
struct spnl_timer_value {
    struct bpf_timer t;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spnl_timer_value);
} spnl_timer_map SEC(".maps");

/* forward decl for the callback so the arm prog can reference it
 * before the body is emitted (codegen emits cb after the map). */
static int spnl_timer_cb_@NAME@(void *map, int *key, struct spnl_timer_value *v);
