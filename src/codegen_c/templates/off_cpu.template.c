/* per-unit off-CPU tracking (ts + stack id per pid).
 * off_cpu_start(pid) records when a task goes off-CPU; off_cpu_observe(pid)
 * fires when it comes back, bins (stack_id -> total off-CPU ns) via
 * the keyed hist. */
struct spnl_off_cpu_entry {
    __u64 ts;
    __u32 stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct spnl_off_cpu_entry);
    __uint(max_entries, 10240);
} bpf_off_cpu SEC(".maps");

/* off_cpu_start: capture (ktime_ns, stack_id) for the going-off task.
 * ctx must be the program's bpf_get_stackid-compatible context. */
static __noinline __s64 spnl_off_cpu_start(__u32 pid, void *ctx)
{
    struct spnl_off_cpu_entry e;
    e.ts       = bpf_ktime_get_ns();
    e.stack_id = (__u32)bpf_get_stackid(ctx, &bpf_stacks, 0);
    bpf_map_update_elem(&bpf_off_cpu, &pid, &e, BPF_ANY);
    return 0;
}

/* off_cpu_observe: if pid has a stored entry, compute delta = now - ts,
 * bin into the keyed log2 hist under key=stack_id, then drop the
 * entry. Returns delta ns (or 0 if no entry). */
static __noinline __s64 spnl_off_cpu_observe(__u32 pid)
{
    struct spnl_off_cpu_entry *e =
        bpf_map_lookup_elem(&bpf_off_cpu, &pid);
    if (!e) return 0;
    __u64 delta    = bpf_ktime_get_ns() - e->ts;
    __u32 stack_id = e->stack_id;
    bpf_map_delete_elem(&bpf_off_cpu, &pid);

    /* Inline hist_observe_by(stack_id, delta) - keyed log2 hist. */
    __u64 k = (__u64)stack_id;
    struct spnl_hist_struct *cur =
        bpf_map_lookup_elem(&bpf_hist_keyed, &k);
    if (!cur) {
        __u32 zk = 0;
        struct spnl_hist_struct *zero =
            bpf_map_lookup_elem(&bpf_hist_keyed_zero, &zk);
        if (!zero) return (__s64)delta;
        bpf_map_update_elem(&bpf_hist_keyed, &k, zero, BPF_NOEXIST);
        cur = bpf_map_lookup_elem(&bpf_hist_keyed, &k);
        if (!cur) return (__s64)delta;
    }
    __u32 slot = (__u32)spnl_hist_log2((__s64)delta);
    if (slot >= 64) return (__s64)delta;
    __sync_fetch_and_add(&cur->buckets[slot], 1);
    return (__s64)delta;
}
