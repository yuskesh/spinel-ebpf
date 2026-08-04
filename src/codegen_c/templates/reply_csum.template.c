/* Roadmap #4/#5b: fold a 32-bit ones-complement sum to 16 bits. */
static __always_inline __u16 spnl_reply_csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}
static __always_inline __u16 spnl_reply_csum_tcp(__be32 saddr, __be32 daddr,
                                                 __u32 len, __u32 csum)
{
    __u64 s = csum;
    s += (__u32)saddr;
    s += (__u32)daddr;
    s += bpf_htons(6 + len);  /* IPPROTO_TCP */
    while (s >> 32) s = (s & 0xffffffff) + (s >> 32);
    return spnl_reply_csum_fold((__u32)s);
}
