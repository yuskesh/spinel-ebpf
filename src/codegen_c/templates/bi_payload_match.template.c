/* Roadmap #5a: TCP payload starts with @PREFIX@ ? */
static __noinline __s64 spnl_payload_match@ID@(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != bpf_htons(0x0800)) return 0;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return 0;
    if (iph->protocol != 6) return 0;  /* IPPROTO_TCP */
    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph)) return 0;
    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);
    if ((void *)(tcp + 1) > data_end) return 0;
    __u32 thl = tcp->doff * 4;
    if (thl < 20) return 0;
    const char *p = (const char *)tcp + thl;
    if ((void *)(p + @LEN@) > data_end) return 0;
    @CMP@
    return 1;
}
