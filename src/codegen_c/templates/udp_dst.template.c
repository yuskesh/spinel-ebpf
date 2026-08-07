/* === where this datagram is actually going === */

/* `sock_dport(sk)` answers "what peer is this socket connected to". For a UDP
 * send that is only the same question when the socket IS connected. udp_sendmsg
 * itself makes the distinction first thing it does: an address in msg_name wins,
 * and only when there is none does it fall back to the connected peer (and
 * returns -EDESTADDRREQ if there is no peer either).
 *
 * A probe written against sock_dport therefore reports nothing at all for an
 * unconnected sender -- skc_dport is 0, so a `== 53` filter is simply false.
 * That is not a rare shape: dnsmasq forwards upstream with a bare sendto(),
 * because one socket serves many destinations. glibc, python, busybox and Go
 * all connect, which is why every resolver measured up to now came through.
 *
 * These two fold the kernel's own rule in, so the author does not have to know
 * it -- and cannot get it half right, which is what makes the failure silent.
 *
 * SEND hooks only. On udp_recvmsg, msg_name is an OUTPUT: the kernel is about
 * to write the sender's address there, so reading it at entry interprets
 * uninitialised bytes as a port. The receive side has no equivalent question --
 * who sent the datagram is not known until the call returns -- so a receive-side
 * filter really is limited to the socket's connected peer, and that limit is
 * named rather than papered over.
 */
static __noinline __s64 spnl_udp_dport(struct sock *sk, struct msghdr *msg)
{
    void *nm = msg ? BPF_CORE_READ(msg, msg_name) : (void *)0;
    if (nm) {
        /* AF_INET/AF_INET6 are UAPI #defines, not an enum, so there is nothing
         * in BTF to relocate against -- unlike the iter_type tags next door. */
        __u16 fam = BPF_CORE_READ((struct sockaddr *)nm, sa_family);
        if (fam == 2)  return (__s64)(__u16)bpf_ntohs(BPF_CORE_READ((struct sockaddr_in *)nm, sin_port));
        if (fam == 10) return (__s64)(__u16)bpf_ntohs(BPF_CORE_READ((struct sockaddr_in6 *)nm, sin6_port));
        return 0;
    }
    if (!sk) return 0;
    return (__s64)(__u16)bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __noinline __s64 spnl_udp_daddr(struct sock *sk, struct msghdr *msg)
{
    void *nm = msg ? BPF_CORE_READ(msg, msg_name) : (void *)0;
    if (nm) {
        __u16 fam = BPF_CORE_READ((struct sockaddr *)nm, sa_family);
        if (fam == 2) return (__s64)(__u32)bpf_ntohl(BPF_CORE_READ((struct sockaddr_in *)nm, sin_addr.s_addr));
        return 0;   /* AF_INET6 has no IPv4 address to give back; ask sock_daddr6_* */
    }
    if (!sk) return 0;
    return (__s64)(__u32)bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
}
