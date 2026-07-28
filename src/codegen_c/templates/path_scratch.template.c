/* === per-unit d_path scratch buffer (path_starts_with) === */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[4096]);
} @UNIT@_path_scratch SEC(".maps");
