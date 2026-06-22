/* EtherType in host byte order, or 0 if frame too short. */
static __noinline __s64 @SIG@
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    return (__s64)bpf_ntohs(eth->h_proto);
}
