/* === capabilities / namespaces ===
 *
 * Everything here reads the CURRENT TASK, which is why the codegen refuses these
 * builtins outside a process-context hook (cc_require_task_ctx). Measured: the
 * identical read in an XDP program run by packets from another machine reports a
 * CPU burner's capability set, with no error and no zero.
 *
 * The reads themselves are the same CO-RE bpf_probe_read_kernel that kfield
 * uses, so the untrusted-pointer rule applies here too: chains, not derefs.
 */

/* kernel_cap_t has been `struct { u64 val; }` since Linux 6.3 (it was
 * `__u32 cap[2]` before). The codegen compiles against the TARGET's vmlinux.h,
 * so on an older kernel this line fails at clang with the field name in the
 * message rather than silently reading half a mask. */
#define SPNL_CAPS(set) \
    ((__u64)BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), cred, set.val))

/* A capability is a BIT INDEX, not a mask: CAP_SYS_ADMIN is 21. `caps & 21`
 * tests bits 0/2/4 and returns 21 whether or not the process has CAP_SYS_ADMIN
 * (measured -- identical in both runs). So the shift lives here and the caller
 * never writes it. `n` is a compile-time constant at every call site the codegen
 * emits, which is what collapses this to one instruction. */
#define SPNL_HAS_CAP(set, n)  ((__s64)((SPNL_CAPS(set) >> (n)) & 1))

/* The task's OWN pid namespace. nsproxy->pid_ns_for_children is the namespace
 * this task's CHILDREN get, and it is a different namespace for any task that
 * called unshare(CLONE_NEWPID) without forking -- measured, in a run where the
 * two differ and both are ordinary-looking inode numbers. thread_pid->numbers is
 * a flexible array indexed at runtime by ->level, so the last hop is pointer
 * arithmetic; vmlinux.h applies preserve_access_index to every record, so the
 * offset of `numbers` is still CO-RE-relocated. A NULL or unreadable pid leaves
 * the copy zeroed and the read yields 0. */
static __always_inline __s64 spnl_pid_ns_inum(void)
{
    struct pid *p = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), thread_pid);
    unsigned int lvl = BPF_CORE_READ(p, level);
    struct upid u = {};
    bpf_probe_read_kernel(&u, sizeof(u), (const void *)&p->numbers[lvl & 31]);
    return (__s64)BPF_CORE_READ(u.ns, ns.inum);
}
