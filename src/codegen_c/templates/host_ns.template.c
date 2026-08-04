/* === the initial namespaces (in_host_ns) ===
 *
 * "is this the host namespace" is a comparison against a number the kernel hands
 * nobody. Three candidate sources were measured:
 *
 *   typed ksym    extern struct nsproxy init_nsproxy __ksym;
 *                 LOAD_FAIL -- "not found in kernel BTF". vmlinux BTF carried
 *                 334 VARs on the kernel measured and none of them was an init_*.
 *   untyped ksym  the form below. libbpf resolves it from /proc/kallsyms; the
 *                 address it baked in matched kallsyms exactly, and the two
 *                 independent chains (init_nsproxy and init_task->nsproxy) agree.
 *   userspace     read /proc/1/ns/* at load time and patch .rodata. This is what
 *                 Tetragon-style agents do, and it is WRONG for the deployment
 *                 this project cares about: inside a container /proc/1 is the
 *                 CONTAINER's init, so it reported mnt 4026532237 where the real
 *                 initial namespace is 4026531832 -- off by a namespace and
 *                 still a perfectly ordinary inode number.
 *
 * Consequences of the ksym form, stated rather than discovered: the symbols are
 * resolved at LOAD time against the running kernel (so they cannot go stale),
 * and a kernel that does not export them fails to load with the symbol named.
 * That needs /proc/kallsyms with real addresses, i.e. root -- which eBPF probes
 * already require.
 */
extern const void init_nsproxy __ksym;
extern const void init_user_ns __ksym;

#define SPNL_HOST_NS(member) \
    ((__s64)BPF_CORE_READ((struct nsproxy *)&init_nsproxy, member, ns.inum))
#define SPNL_HOST_USER_NS() \
    ((__s64)BPF_CORE_READ((struct user_namespace *)&init_user_ns, ns.inum))
