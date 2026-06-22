/* L4 @SUFFIX@ (TCP or UDP, IPv4 or IPv6) in host byte order, 0 otherwise. */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto == bpf_htons(0x0800)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return 0;
        if (iph->protocol != 6 && iph->protocol != 17) return 0;
        __u32 ihl = iph->ihl * 4;
        if (ihl < sizeof(*iph)) return 0;
        char *l4 = (char *)iph + ihl;
        if (l4 + 4 > (char *)data_end) return 0;
        __be16 *p = (__be16 *)(l4 + @OFF@);
        return (__s64)bpf_ntohs(*p);
    }
    if (eth->h_proto == bpf_htons(0x86DD)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return 0;
        if (ip6h->nexthdr != 6 && ip6h->nexthdr != 17) return 0;
        char *l4 = (char *)(ip6h + 1);
        if (l4 + 4 > (char *)data_end) return 0;
        __be16 *p = (__be16 *)(l4 + @OFF@);
        return (__s64)bpf_ntohs(*p);
    }
    return 0;
}
