/* STACK (LIFO) map. lifo_push(v) / lifo_pop(). */
struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(max_entries, 1024);
    __type(value, __s64);
} bpf_lifo SEC(".maps");

static __always_inline __s64 spnl_lifo_push(__s64 v)
{
    return (__s64)bpf_map_push_elem(&bpf_lifo, &v, BPF_ANY);
}
static __always_inline __s64 spnl_lifo_pop(void)
{
    __s64 v = 0;
    return bpf_map_pop_elem(&bpf_lifo, &v) == 0 ? v : 0;
}
