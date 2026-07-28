{
    __u32 _drt@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_dns_recv_stash_st _drs@E@ = {};
    _drs@E@.sk = (__u64)(unsigned long)(@SK@);
    _drs@E@.buf = (__u64)(unsigned long)BPF_CORE_READ((struct msghdr *)(unsigned long)(@MSG@), msg_iter.__ubuf_iovec.iov_base);
    bpf_map_update_elem(&@UNIT@_dns_recv_stash, &_drt@E@, &_drs@E@, BPF_ANY);
}
