/* L4 protocol (TCP=6, UDP=17, ICMP=1, ICMPv6=58), or 0 if not
 * IPv4 nor IPv6 / truncated.
 * For IPv6 we return ip6h->nexthdr directly - if it's an
 * extension header (Hop-by-Hop=0, Routing=43, Fragment=44, ...)
 * the caller sees that value as-is (extension header walking is
 * out of scope for this builtin). */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto == bpf_htons(0x0800)) {  /* ETH_P_IP */
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return 0;
        return (__s64)iph->protocol;
    }
    if (eth->h_proto == bpf_htons(0x86DD)) {  /* ETH_P_IPV6 */
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return 0;
        return (__s64)ip6h->nexthdr;
    }
    return 0;
}
