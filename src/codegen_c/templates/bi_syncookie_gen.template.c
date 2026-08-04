/* Roadmap #3: generate a TCP SYN cookie for the current packet (IPv4/TCP).
 * Returns the kfunc result (>=0, cookie in the low half and MSS in the high) or
 * negative on error / non-TCP. kfunc resolved from vmlinux.h (spinel kernel BTF).
 *
 * THE FRAME IS RESIZED. bpf_tcp_raw_gen_syncookie_ipv4 requires TCP_MAXLEN
 * (60) bytes readable at `tcp` whatever the actual header length is, so the frame
 * has to be grown to a 60-byte TCP header before the call. That is not an
 * optimisation and it is not optional -- measured, all three variants on 7.1.5
 * Three variants were measured:
 *
 *   A  bound by the ACTUAL header length (what the retired Ruby oracle emitted,
 *      offsets)                                   LOAD_FAIL
 *        invalid access to packet, off=34 size=60, R2(id=0,off=34,r=54)
 *   B  grow + re-read ctx->data/data_end, no explicit re-check   LOAD_FAIL
 *        invalid access to packet, off=14 size=20, R1(id=0,off=14,r=0)
 *   C  grow + compiler barrier + EXPLICIT 60-byte bound          LOAD_OK   <- this
 *
 * B is the one worth reading. The lesson was originally recorded as "kernel-side
 * adjust_tail(0) is a no-op, but the verifier's register tracking LEARNS
 * TCP_MAXLEN readable from it". On 7.1.5 it does not: after adjust_tail the
 * packet pointers come back with r=0 and only the explicit compares restore
 * them. That fix worked because the code also had the compares; it credited
 * the wrong half.
 *
 * The compiler barrier is kept for the reason it was measured: without it clang
 * re-reads data_end as `ctx+4`, which the verifier treats as a modified ctx ptr.
 *
 * Consequence for the caller: after this returns, the packet carries a 60-byte
 * TCP header. `tcp_reply_synack(cookie)` -- the only consumer of a cookie --
 * re-parses and shrinks it to 14+20+24 at the end, and the pair is measured
 * LOAD_OK together (variant D). If you want the whole SYN -> SYN-ACK step in one
 * call without an intermediate grown frame, use `tcp_synack_cookie`. */
static __noinline __s64 spnl_tcp_syncookie_gen(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != bpf_htons(0x0800)) return -1;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return -1;
    if (iph->protocol != 6) return -1;           /* IPPROTO_TCP */
    if (iph->ihl != 5) return -1;                /* standard 20-byte IP header */
    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
    if ((void *)(tcp + 1) > data_end) return -1;
    __u32 thl_in = tcp->doff * 4;
    if (thl_in < 20 || thl_in > 60) return -1;
    if ((char *)tcp + thl_in > (char *)data_end) return -1;

    /* grow to a 60-byte TCP header (the kfunc needs the room) */
    int delta = 60 - (int)thl_in;
    if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta) != 0) return -1;
    /* Compiler barrier so clang re-reads ctx->data_end with a clean LDX
     * instead of materialising `ctx+4` (a modified ctx ptr to the verifier). */
    asm volatile("" ::: "memory");
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    iph = (void *)(eth + 1);
    if ((char *)iph + 60 > (char *)data_end) return -1;
    tcp = (struct tcphdr *)((char *)iph + 20);
    if ((char *)tcp + 60 > (char *)data_end) return -1;
    return (__s64)bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in);
}
