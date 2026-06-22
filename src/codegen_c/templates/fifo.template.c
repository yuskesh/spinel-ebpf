/* QUEUE (FIFO) map. fifo_push(v) / fifo_pop(). */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1024);
    __type(value, __s64);
} bpf_fifo SEC(".maps");

static __always_inline __s64 spnl_fifo_push(__s64 v)
{
    return (__s64)bpf_map_push_elem(&bpf_fifo, &v, BPF_ANY);
}
static __always_inline __s64 spnl_fifo_pop(void)
{
    __s64 v = 0;
    return bpf_map_pop_elem(&bpf_fifo, &v) == 0 ? v : 0;
}
