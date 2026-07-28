{
    __u64 _grg@E@ = (__u64)(ctx->regs[28]);   /* arm64 g register (goroutine) - stable across a blocking Read, unlike tid */
    struct @UNIT@_http_stash_st _grs@E@ = {};
    _grs@E@.sk  = (__u64)(unsigned long)(@CONN@);
    _grs@E@.buf = (__u64)(unsigned long)(@PTR@);
    bpf_map_update_elem(&@UNIT@_go_recv_stash, &_grg@E@, &_grs@E@, BPF_ANY);
}
