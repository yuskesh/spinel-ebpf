/* per-unit log2 histogram (64 buckets). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} bpf_hist SEC(".maps");

/* Verifier-safe integer log2: returns floor(log2(v)) clamped to
 * [0, HISTOGRAM_SLOTS-1]. v<=0 maps to slot 0 so callers don't have
 * to guard against zero observations (it just over-reports the
 * smallest bucket). All comparisons are against compile-time
 * constants so the verifier sees a bounded computation. */
static __noinline __s64 spnl_hist_log2(__s64 v)
{
    __s64 r = 0;
    if (v <= 1) return 0;
    if (v >= (1LL << 32)) { v >>= 32; r += 32; }
    if (v >= (1   << 16)) { v >>= 16; r += 16; }
    if (v >= (1   << 8))  { v >>= 8;  r += 8;  }
    if (v >= (1   << 4))  { v >>= 4;  r += 4;  }
    if (v >= (1   << 2))  { v >>= 2;  r += 2;  }
    if (v >= (1   << 1))  { v >>= 1;  r += 1;  }
    if (r > 63) r = 63;
    return r;
}

static __noinline __s64 spnl_hist_observe(__s64 v)
{
    __u32 slot = (__u32)spnl_hist_log2(v);
    if (slot >= 64) return 0;  /* verifier hand-holding */
    __u64 *cur = bpf_map_lookup_elem(&bpf_hist, &slot);
    if (cur) __sync_fetch_and_add(cur, 1);
    return 0;
}
