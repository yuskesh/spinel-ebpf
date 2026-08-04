/* pure-XDP TCP slice attach for @NAME@ */
SEC("xdp")
int @NAME@(struct xdp_md *ctx)
{
    return spnl_tcp_slice_main(ctx);
}
