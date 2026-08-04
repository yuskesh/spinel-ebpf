/* === per-unit ringbuf lost-sample counter ===
 * A bpf_ringbuf_reserve() that returns NULL (the ring filled faster than
 * userspace drained it) would otherwise drop the record silently -- invisible to
 * the drain-layer channel balance report, which can only count what came out.
 * Every emit else-branch bumps this; the runtime reads it at exit and prints the
 * 4th balance-report failure ("dropped by the kernel -- ring full").
 *
 * One PERCPU_ARRAY slot for the whole unit, not one per channel. Per-channel
 * attribution would need a codegen-assigned slot table shared with the glue
 * generator (two generators agreeing on indices) -- a unit-wide total answers the
 * question that matters (were records dropped by ring-full, and about how many)
 * with one map and no cross-generator contract. per-CPU so the bump needs no
 * atomic; the runtime sums the slots. Inspektor Gadget keeps a per-CPU lost
 * counter the same way. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} @UNIT@_lost SEC(".maps");

static __always_inline void spnl_lost_inc(void)
{
    __u32 _z = 0;
    __u64 *_l = bpf_map_lookup_elem(&@UNIT@_lost, &_z);
    if (_l) *_l += 1;
}
