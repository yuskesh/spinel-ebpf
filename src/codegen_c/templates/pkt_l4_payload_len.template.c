/* TCP/UDP payload length in bytes (IP total length minus IP
 * and L4 header sizes). 0 if not IPv4/IPv6 TCP/UDP or truncated.
 * Useful for distinguishing "empty ACK" packets (kernel-generated
 * spurious control packets) from data carriers.
 * For IPv6, ip6h->payload_len already excludes
 * the IPv6 header (unlike IPv4 tot_len), so we just subtract the
 * L4 header size. Extension headers are out of scope. */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto == bpf_htons(0x0800)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return 0;
        __u32 ihl = iph->ihl * 4;
        if (ihl < sizeof(*iph)) return 0;
        __u32 ip_tot = bpf_ntohs(iph->tot_len);
        __u32 l4_total = (ip_tot > ihl) ? (ip_tot - ihl) : 0;
        if (iph->protocol == 6) {  /* IPPROTO_TCP */
            char *l4 = (char *)iph + ihl;
            if (l4 + 13 > (char *)data_end) return 0;
            __u32 doff = (((__u8)l4[12]) >> 4) * 4;
            if (doff < 20) return 0;
            return (__s64)((l4_total > doff) ? (l4_total - doff) : 0);
        } else if (iph->protocol == 17) {  /* IPPROTO_UDP */
            return (__s64)((l4_total > 8) ? (l4_total - 8) : 0);
        }
        return 0;
    }
    if (eth->h_proto == bpf_htons(0x86DD)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return 0;
        __u32 l4_total = bpf_ntohs(ip6h->payload_len);
        if (ip6h->nexthdr == 6) {  /* IPPROTO_TCP */
            char *l4 = (char *)(ip6h + 1);
            if (l4 + 13 > (char *)data_end) return 0;
            __u32 doff = (((__u8)l4[12]) >> 4) * 4;
            if (doff < 20) return 0;
            return (__s64)((l4_total > doff) ? (l4_total - doff) : 0);
        } else if (ip6h->nexthdr == 17) {  /* IPPROTO_UDP */
            return (__s64)((l4_total > 8) ? (l4_total - 8) : 0);
        }
        return 0;
    }
    return 0;
}
