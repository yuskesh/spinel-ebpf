{
    __u32 _ot@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_offcpu_stash_st _os@E@ = {};
    _os@E@.buf = (__u64)(unsigned long)spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
    bpf_map_update_elem(&@UNIT@_offcpu_stash, &_ot@E@, &_os@E@, BPF_ANY);
}
