{
    __u32 _rt@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_redis_stash_st _rs@E@ = {};
    _rs@E@.sk = (__u64)(unsigned long)(@SK@);
    _rs@E@.buf = (__u64)(unsigned long)BPF_CORE_READ((struct msghdr *)(unsigned long)(@MSG@), msg_iter.__ubuf_iovec.iov_base);
    bpf_map_update_elem(&@UNIT@_redis_recv_stash, &_rt@E@, &_rs@E@, BPF_ANY);
}
