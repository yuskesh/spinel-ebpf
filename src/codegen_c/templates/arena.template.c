/* bpf_arena - sparse, mmap-able shared memory backing arena_set/get. */
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1); /* pages; 1 page = 512 u64 slots */
#if defined(__TARGET_ARCH_arm64)
    __ulong(map_extra, (1ull << 32)); /* user mmap base (arm64) */
#else
    __ulong(map_extra, (1ull << 44)); /* user mmap base (x86-64) */
#endif
} @UNIT@_arena SEC(".maps");

/* Lives in the arena (placed at load time); index masked to stay in-page. */
__u64 __arena @UNIT@_arena_data[512];
