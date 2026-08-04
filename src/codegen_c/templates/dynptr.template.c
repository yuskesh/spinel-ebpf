/* bpf_dynptr-backed XDP byte access. vmlinux.h (CO-RE BTF)
 * already declares bpf_dynptr_from_xdp / bpf_dynptr_slice as
 * `__weak __ksym` externs with `u64 offset`, so we don't redeclare
 * them here -- just use them.
 *
 * Read a single byte from an XDP frame at runtime offset. The
 * verifier validates the 1-byte access via the dynptr -- no manual
 * `data + off > data_end` check needed in the caller.
 *
 * Re-ported from the retired Ruby code generator, having been lost in the port
 * to C and withdrawn as unimplemented. The body below is
 * byte-for-byte the oracle's, and it was measured to load unchanged on
 * 7.1.5-ebpf / clang 19.1.7 / -mcpu=v1 -- unlike the task iterator, whose
 * oracle form the current verifier rejected. `buffer__szk` in the kfunc
 * signature means the size must be a compile-time constant, which is why
 * the 1-byte read is the whole surface. */
static __noinline __s64 spnl_pkt_dynptr_byte_at(struct xdp_md *ctx, __s64 off)
{
    if (off < 0) return -1;
    struct bpf_dynptr dp;
    if (bpf_dynptr_from_xdp(ctx, 0, &dp) < 0) return -1;
    __u8 buf;
    __u8 *p = bpf_dynptr_slice(&dp, (__u64)off, &buf, 1);
    if (!p) return -1;
    return (__s64)*p;
}
