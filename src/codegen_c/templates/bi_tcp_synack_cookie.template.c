/* Build the SYN-ACK (swap, seq=cookie, ack=client_seq+1, MSS option, csums)
 * into the grown packet. Kept as a separate __always_inline helper taking
 * the re-bounded pointers -- like the slice bundle's build_synack/recompute_
 * csums -- so the heavy build/csum register pressure does NOT push the
 * compiler to materialise `ctx+4` for the post-grow data_end re-read
 * (verifier "modified ctx ptr"). */
static __always_inline int spnl_synack_build(struct ethhdr *eth, struct iphdr *iph,
                                             struct tcphdr *tcp, __u32 cookie_seq,
                                             __u16 mss, __u32 client_seq)
{
    __u8 mac[6];
    __builtin_memcpy(mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, mac, 6);
    __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
    __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;
    tcp->seq     = bpf_htonl(cookie_seq);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->doff = 6;
    ((__u8 *)tcp)[13] = 0x12;   /* SYN|ACK */
    tcp->window  = bpf_htons(65535);
    tcp->urg_ptr = 0;
    __u8 *o = (__u8 *)tcp + 20;
    o[0] = 2; o[1] = 4;          /* TCPOPT_MSS, len 4 */
    o[2] = (mss >> 8) & 0xff;
    o[3] = mss & 0xff;
    iph->tot_len = bpf_htons(20 + 24);
    iph->ttl = 64;
    iph->id  = 0;
    iph->check = 0;
    __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
    if (v < 0) return -1;
    iph->check = spnl_reply_csum_fold((__u32)v);
    tcp->check = 0;
    v = bpf_csum_diff(0, 0, (void *)tcp, 24, 0);
    if (v < 0) return -1;
    tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 24, (__u32)v);
    return 0;
}

/* Roadmap #4b': SYN -> SYN-ACK with a SYN cookie + MSS option, the original
 * bundle sequence (grow-to-60, gen, build, shrink). Returns 0/-1. */
static __noinline __s64 spnl_tcp_synack_cookie(struct xdp_md *ctx)
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
    __u32 thl_in = tcp->doff * 4;
    if (thl_in < 20 || (char *)tcp + thl_in > (char *)data_end) return -1;

    /* grow to a 60-byte TCP header (the kfunc needs the room) */
    int delta = 60 - (int)thl_in;
    if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta) != 0) return -1;
    /* Compiler barrier so clang re-reads ctx->data_end with a clean
     * LDX `*(u32*)(ctx+4)` instead of materialising `r2 = ctx+4; *r2` (which
     * the verifier rejects after adjust_tail as a "modified ctx ptr"). The
     * cheap C-level workarounds (constant shrink / __always_inline build
     * split, or reordering data_end first) did NOT help; this barrier -- the
     * standard idiom for post-adjust_tail re-validation -- is what makes the
     * grow path load, with the existing __noinline structure untouched. */
    asm volatile("" ::: "memory");
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    iph = (void *)(eth + 1);
    if ((char *)iph + 60 > (char *)data_end) return -1;
    tcp = (struct tcphdr *)((char *)iph + 20);
    if ((char *)tcp + 60 > (char *)data_end) return -1;

    __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in);
    if (cookie < 0) return -1;
    __u16 mss = (__u16)(cookie >> 32);
    if (mss == 0) mss = 1460;
    if (spnl_synack_build(eth, iph, tcp, (__u32)cookie, mss, bpf_ntohl(tcp->seq)) < 0) return -1;

    /* shrink: after the grow the (payload-less) SYN is EXACTLY
     * eth(14)+ip(20)+tcp(60) = 94 bytes, so the delta is constant 58-94. */
    if (bpf_xdp_adjust_tail(ctx, (int)(14 + 20 + 24) - (int)(14 + 20 + 60)) != 0) return -1;
    return 0;
}
