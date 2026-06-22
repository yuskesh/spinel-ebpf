/* per-task local storage. task_store(v) / task_load() read+write
 * a value scoped to the current task_struct (no explicit key). */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __s64);
} bpf_task_store SEC(".maps");

/* __always_inline: the PTR_TRUSTED task from bpf_get_current_task_btf()
 * must reach bpf_task_storage_get in the program's own context, not
 * across a __noinline sub-prog boundary (where it degrades and the
 * storage silently fails to persist). */
static __always_inline __s64 spnl_task_load(void)
{
    struct task_struct *t = bpf_get_current_task_btf();
    __s64 *v = bpf_task_storage_get(&bpf_task_store, t, 0, 0);
    return v ? *v : 0;
}

static __always_inline __s64 spnl_task_store(__s64 value)
{
    struct task_struct *t = bpf_get_current_task_btf();
    __s64 *v = bpf_task_storage_get(&bpf_task_store, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (v) { *v = value; }
    return value;
}

static __always_inline __s64 spnl_task_incr(__s64 delta)
{
    struct task_struct *t = bpf_get_current_task_btf();
    __s64 *v = bpf_task_storage_get(&bpf_task_store, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    *v += delta;
    return *v;
}

/* single-get read-modify-write - store `value`, return the prior
 * value. One bpf_task_storage_get so it stays clear of the two-get
 * aliasing quirk. */
static __always_inline __s64 spnl_task_swap(__s64 value)
{
    struct task_struct *t = bpf_get_current_task_btf();
    __s64 *v = bpf_task_storage_get(&bpf_task_store, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    __s64 old = *v;
    *v = value;
    return old;
}
