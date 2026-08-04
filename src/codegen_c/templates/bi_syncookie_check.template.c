/* Roadmap #3: validate a TCP SYN cookie for the
 * current packet (IPv4/TCP). Returns the kfunc result (>=0) or negative
 * on error / non-TCP. kfunc resolved from vmlinux.h (spinel kernel BTF).
 * Bounds use the ACTUAL TCP header length. Unlike its `gen` sibling this one
 * needs nothing more: bpf_tcp_raw_check_syncookie_ipv4 takes (iph, tcp) and does
 * NOT demand TCP_MAXLEN readable, so the packet is never resized -- which is
 * also why it may run on the handshake ACK, a frame it must not disturb.
 * Measured LOAD_OK standalone on 7.1.5. */
static __noinline __s64 spnl_tcp_syncookie_check(struct xdp_md *ctx)
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
    __u32 thl = tcp->doff * 4;
    if (thl < 20 || thl > 60) return -1;
    if ((char *)tcp + thl > (char *)data_end) return -1;
    return (__s64)bpf_tcp_raw_check_syncookie_ipv4(iph, tcp);
}
