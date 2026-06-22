/* TCP flag byte (host-order), 0 if not TCP or truncated.
 * RFC 793 section 3.1: flags live in the 13th byte of the TCP header
 * (offset of data_offset|reserved|flags). We mask off the data
 * offset upper nibble so the caller sees a clean 8-bit field.
 * IPv6 is handled too (extension headers out of scope). */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto == bpf_htons(0x0800)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return 0;
        if (iph->protocol != 6) return 0;  /* IPPROTO_TCP */
        __u32 ihl = iph->ihl * 4;
        if (ihl < sizeof(*iph)) return 0;
        char *l4 = (char *)iph + ihl;
        if (l4 + 14 > (char *)data_end) return 0;
        __u8 flags = (__u8)l4[13];
        return (__s64)flags;
    }
    if (eth->h_proto == bpf_htons(0x86DD)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return 0;
        if (ip6h->nexthdr != 6) return 0;  /* IPPROTO_TCP */
        char *l4 = (char *)(ip6h + 1);
        if (l4 + 14 > (char *)data_end) return 0;
        __u8 flags = (__u8)l4[13];
        return (__s64)flags;
    }
    return 0;
}
