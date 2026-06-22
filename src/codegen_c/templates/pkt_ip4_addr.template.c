/* IPv4 @DIR@ address in host byte order, or 0 if not IPv4. */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != bpf_htons(0x0800)) return 0;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return 0;
    return (__s64)bpf_ntohl(iph->@ADDR@);
}
