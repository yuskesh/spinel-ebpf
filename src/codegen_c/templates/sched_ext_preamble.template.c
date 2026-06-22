/* sched_ext constant macros. scx_bpf_* kfunc declarations
 * already live in vmlinux.h (BTF-generated, marked __weak __ksym),
 * so we don't redeclare them here. */

/* SCX DSQ id helpers (see kernel: include/linux/sched/ext.h). */
#ifndef SCX_DSQ_FLAG_BUILTIN
#define SCX_DSQ_FLAG_BUILTIN (1ULL << 63)
#endif
#ifndef SCX_DSQ_GLOBAL
#define SCX_DSQ_GLOBAL   (SCX_DSQ_FLAG_BUILTIN | 1ULL)
#endif
#ifndef SCX_DSQ_LOCAL
#define SCX_DSQ_LOCAL    (SCX_DSQ_FLAG_BUILTIN | 0ULL)
#endif
#ifndef SCX_SLICE_DFL
#define SCX_SLICE_DFL    20000000ULL    /* 20 ms */
#endif
#ifndef SCX_SLICE_INF
#define SCX_SLICE_INF    (~0ULL)
#endif
#ifndef SCX_KICK_PREEMPT
#define SCX_KICK_PREEMPT (1U << 0)
#endif
#ifndef SCX_ENQ_PREEMPT
#define SCX_ENQ_PREEMPT  (1ULL << 32)
#endif
