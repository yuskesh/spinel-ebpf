/* IPv6 @WHICH@ address @HALF@ half (host byte order), 0 if not IPv6. */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != bpf_htons(0x86DD)) return 0;  /* ETH_P_IPV6 */
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) return 0;
    __be32 a0 = ip6h->@FIELD@.in6_u.u6_addr32[@I0@];
    __be32 a1 = ip6h->@FIELD@.in6_u.u6_addr32[@I1@];
    __u64 v = ((__u64)bpf_ntohl(a0) << 32) | (__u64)bpf_ntohl(a1);
    return (__s64)v;
}
