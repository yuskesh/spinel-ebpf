/* map-in-map. 4 inner ARRAY maps + an
 * ARRAY_OF_MAPS outer that libbpf populates with them at load time. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 64);
} bpf_mim_inner0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 64);
} bpf_mim_inner1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 64);
} bpf_mim_inner2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 64);
} bpf_mim_inner3 SEC(".maps");

struct mim_inner_t {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 64);
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 4);
    __type(key, __u32);
    __array(values, struct mim_inner_t);
} bpf_mim_outer SEC(".maps") = {
    .values = { &bpf_mim_inner0, &bpf_mim_inner1, &bpf_mim_inner2, &bpf_mim_inner3 },
};

static __always_inline __s64 spnl_mim_at(__s64 g, __s64 k)
{
    __u32 gi = (__u32)g;
    void *inner = bpf_map_lookup_elem(&bpf_mim_outer, &gi);
    if (!inner) return 0;
    __u32 ki = (__u32)k;
    return (__s64)(unsigned long)bpf_map_lookup_elem(inner, &ki);
}
static __always_inline __s64 spnl_mim_inc(__s64 g, __s64 k)
{
    __s64 *v = (__s64 *)(unsigned long)spnl_mim_at(g, k);
    if (!v) return 0;
    __sync_fetch_and_add(v, 1);
    return *v;
}
static __always_inline __s64 spnl_mim_get(__s64 g, __s64 k)
{
    __s64 *v = (__s64 *)(unsigned long)spnl_mim_at(g, k);
    return v ? *v : 0;
}
