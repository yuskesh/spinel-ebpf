{
    __u32 _drt@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_dns_recv_stash_st _drs@E@ = {};
    _drs@E@.sk = (__u64)(unsigned long)(@SK@);
    _drs@E@.buf = (__u64)(unsigned long)spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
    bpf_map_update_elem(&@UNIT@_dns_recv_stash, &_drt@E@, &_drs@E@, BPF_ANY);
}
