/* Roadmap #5b: response payload #@ID@ (@LEN@ bytes). */
static const __u8 spnl_reply_body@ID@[@LEN@] = {
    @INIT@
};
/* Write the response INTO the existing packet (overwriting the
 * request payload), recompute checksums, and resize LAST. We never re-read
 * ctx->data/data_end after bpf_xdp_adjust_tail (the verifier rejects that:
 * "modified ctx ptr") -- exactly the order the slice bundle uses. The incoming
 * request must have room for the response payload (GET lines normally do). */
static __noinline __s64 spnl_tcp_reply_data@ID@(struct xdp_md *ctx, __u32 seq, __u32 ack)
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

    /* the response must fit in the current packet (we resize down after) */
    __u8 *out = (__u8 *)tcp + 20;
    if ((void *)(out + @LEN@) > data_end) return -1;

    /* swap endpoints */
    __u8 mac[6];
    __builtin_memcpy(mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, mac, 6);
    __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
    __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;

    /* header: seq/ack, FIN|PSH|ACK, doff=5, window */
    tcp->seq     = bpf_htonl(seq);
    tcp->ack_seq = bpf_htonl(ack);
    tcp->doff = 5;
    ((__u8 *)tcp)[13] = 0x19;  /* FIN|PSH|ACK */
    tcp->window  = bpf_htons(65535);
    tcp->urg_ptr = 0;

    /* payload into the existing packet space */
    __builtin_memcpy(out, spnl_reply_body@ID@, @LEN@);
    iph->tot_len = bpf_htons(20 + 20 + @LEN@);
    iph->ttl = 64;
    iph->id  = 0;

    /* checksums (constant lengths) */
    iph->check = 0;
    __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
    if (v < 0) return -1;
    iph->check = spnl_reply_csum_fold((__u32)v);
    tcp->check = 0;
    v = bpf_csum_diff(0, 0, (void *)tcp, 20 + @LEN@, 0);
    if (v < 0) return -1;
    tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20 + @LEN@, (__u32)v);

    /* resize to the final length LAST (usually a shrink); no ctx re-read */
    __u32 want = sizeof(struct ethhdr) + 20 + 20 + @LEN@;
    __u32 cur  = (__u32)((long)data_end - (long)data);
    if (cur != want && bpf_xdp_adjust_tail(ctx, (int)want - (int)cur) != 0) return -1;
    return 0;
}
