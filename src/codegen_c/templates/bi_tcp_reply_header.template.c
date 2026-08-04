/* Turn the current packet into a header-only TCP reply (seq/ack in host
 * order; flags = TCP flag byte, e.g. TCP_FLAG_SYN|TCP_FLAG_ACK). XDP only.
 * Returns 0 on success, -1 on error. Caller returns XDP_TX. */
static __noinline __s64 spnl_tcp_reply_header(struct xdp_md *ctx, __u32 seq, __u32 ack, __u8 flags)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != bpf_htons(0x0800)) return -1;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return -1;
    if (iph->protocol != 6) return -1;     /* IPPROTO_TCP */
    if (iph->ihl != 5) return -1;          /* standard 20-byte IP header only */
    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
    if ((void *)(tcp + 1) > data_end) return -1;  /* 20 bytes available */

    /* swap MAC */
    __u8 mac[6];
    __builtin_memcpy(mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, mac, 6);
    /* swap IP + ports */
    __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
    __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;
    /* normalise to a 20-byte TCP header (no options) so the checksum length
     * is CONSTANT -- a variable bpf_csum_diff length is rejected by the
     * verifier (it bounds-checks the max, but only the min is validated;
     * found end to end). */
    tcp->doff = 5;
    tcp->seq     = bpf_htonl(seq);
    tcp->ack_seq = bpf_htonl(ack);
    ((__u8 *)tcp)[13] = flags;
    tcp->window  = bpf_htons(65535);
    tcp->urg_ptr = 0;
    iph->tot_len = bpf_htons(20 + 20);
    iph->ttl = 64;
    iph->id  = 0;

    /* IP checksum (constant 20 bytes) */
    iph->check = 0;
    __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
    if (v < 0) return -1;
    iph->check = spnl_reply_csum_fold((__u32)v);
    /* TCP checksum (constant 20-byte header, no payload) */
    tcp->check = 0;
    v = bpf_csum_diff(0, 0, (void *)tcp, 20, 0);
    if (v < 0) return -1;
    tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20, (__u32)v);
    return 0;
}
