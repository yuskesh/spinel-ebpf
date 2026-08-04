/* Roadmap #4b: turn the SYN into a SYN-ACK with the MSS option (syncookie).
 * cookie = (__s64)tcp_syncookie_gen. Returns 0/-1; caller returns XDP_TX. */
static __noinline __s64 spnl_tcp_reply_synack(struct xdp_md *ctx, __s64 cookie)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != bpf_htons(0x0800)) return -1;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return -1;
    if (iph->protocol != 6) return -1;
    if (iph->ihl != 5) return -1;
    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
    if ((void *)(tcp + 1) > data_end) return -1;
    /* need 24 bytes of TCP (20 header + 4 MSS option) -- SYN packets have it */
    __u8 *o = (__u8 *)tcp + 20;
    if ((void *)(o + 4) > data_end) return -1;

    __u32 cookie_seq = (__u32)cookie;
    __u16 mss = (__u16)(cookie >> 32);
    if (mss == 0) mss = 1460;
    __u32 client_seq = bpf_ntohl(tcp->seq);

    /* swap endpoints */
    __u8 mac[6];
    __builtin_memcpy(mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, mac, 6);
    __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
    __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;

    tcp->seq     = bpf_htonl(cookie_seq);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->doff = 6;                 /* 24-byte TCP header */
    ((__u8 *)tcp)[13] = 0x12;      /* SYN|ACK */
    tcp->window  = bpf_htons(65535);
    tcp->urg_ptr = 0;
    o[0] = 2; o[1] = 4;            /* TCPOPT_MSS, len 4 */
    o[2] = (mss >> 8) & 0xff;
    o[3] = mss & 0xff;

    iph->tot_len = bpf_htons(20 + 24);
    iph->ttl = 64;
    iph->id  = 0;

    /* checksums: IP 20 bytes, TCP 24 bytes (constant) */
    iph->check = 0;
    __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
    if (v < 0) return -1;
    iph->check = spnl_reply_csum_fold((__u32)v);
    tcp->check = 0;
    v = bpf_csum_diff(0, 0, (void *)tcp, 24, 0);
    if (v < 0) return -1;
    tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 24, (__u32)v);

    /* resize to 14 + 20 + 24 LAST (usually a shrink); no ctx re-read */
    __u32 want = sizeof(struct ethhdr) + 20 + 24;
    __u32 cur  = (__u32)((long)data_end - (long)data);
    if (cur != want && bpf_xdp_adjust_tail(ctx, (int)want - (int)cur) != 0) return -1;
    return 0;
}
