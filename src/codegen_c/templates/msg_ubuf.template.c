/* === msghdr -> user buffer, and the datagram's real destination === */

/* Every builtin that reads the bytes of a send or a receive starts from a
 * `struct msghdr *` and has to answer one question: where in user memory are
 * the bytes? All eleven of them used to answer it the same wrong way --
 *
 *     BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base)
 *
 * -- which is only the answer for ITER_UBUF. `msg_iter` is a tagged union and
 * that member is one of the tags; for ITER_IOVEC the same 8 bytes hold `__iov`,
 * a pointer to the KERNEL's copy of the caller's iovec array (import_iovec
 * copies it in), so the read above hands a kernel address to
 * bpf_probe_read_user, which fails. Measured on a 2-iovec sendmsg: iov_base
 * reported 0xffff80008714bc88 while the payload the process actually sent was
 * at 0xffffe6f60fb8.
 *
 * A single-entry iovec array is NOT affected: the kernel normalises nr_segs==1
 * to ITER_UBUF, which is why writev-style sends of one segment worked and why
 * the bug survived every fixture -- all of them send one buffer.
 *
 * The resolution lives in ONE function on purpose. Eleven call sites each
 * carrying their own union discipline is exactly how a second, disagreeing
 * table gets written.
 */

/* raw_status when the helper below could not name a user buffer at all. Distinct
 * from any errno bpf_probe_read_user can return, so a reader never has to guess
 * which of the two happened. */
#define SPNL_RAW_NO_USER_BUFFER (-1)

static __noinline void *spnl_msg_ubuf(struct msghdr *msg)
{
    if (!msg) return (void *)0;
    /* The enumerator values are read out of the running kernel's BTF rather
     * than baked in, so a renumbered enum cannot silently reclassify a send. */
    __u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
    void *base = (void *)0;
    if (it == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
        base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
    } else if (it == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
        /* __iov always points at the iterator's CURRENT segment (iov_iter_advance
         * walks the pointer forward), so the first entry is the right one at any
         * position, not just at entry. */
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov) base = BPF_CORE_READ(iov, iov_base);
    }
    /* ITER_BVEC / ITER_KVEC / ITER_XARRAY / ITER_DISCARD describe pages or kernel
     * memory: there is no user buffer to read, and saying so is the point --
     * returning a plausible pointer is what produced the zero-filled records. */
    if (!base) return (void *)0;
    /* iov_offset is how far into the current segment the iterator already is.
     * Zero at every capture point this codegen attaches to (all of them are
     * function entries), but reading it makes the contract "the bytes the
     * iterator is about to consume" true wherever the helper is called. */
    return (void *)((__u8 *)base + (unsigned long)BPF_CORE_READ(msg, msg_iter.iov_offset));
}
