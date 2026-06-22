/* per-unit kprobe-to-kretprobe latency timing.
 * key=tid (current_pid_tgid lower 32), value=entry ktime_ns. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} bpf_lat_starts SEC(".maps");

static __noinline __s64 spnl_latency_start(void)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 t   = bpf_ktime_get_ns();
    bpf_map_update_elem(&bpf_lat_starts, &tid, &t, BPF_ANY);
    return 0;
}

static __noinline __s64 spnl_latency_end(void)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *t0 = bpf_map_lookup_elem(&bpf_lat_starts, &tid);
    if (!t0) return 0;
    __u64 delta = bpf_ktime_get_ns() - *t0;
    bpf_map_delete_elem(&bpf_lat_starts, &tid);
    return (__s64)delta;
}
