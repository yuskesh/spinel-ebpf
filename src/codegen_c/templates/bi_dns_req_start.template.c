{
    void *_dqb@E@ = spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
    unsigned char _dqid@E@[2] = {};
    if (_dqb@E@ && bpf_probe_read_user(_dqid@E@, sizeof(_dqid@E@), _dqb@E@) == 0) {
        __u64 _dqkey@E@ = ((__u64)(unsigned long)(@SK@) << 16) | ((__u64)_dqid@E@[0] << 8) | (__u64)_dqid@E@[1];
        __u64 _dqstart@E@ = bpf_ktime_get_ns();
        bpf_map_update_elem(&@UNIT@_dns_pending, &_dqkey@E@, &_dqstart@E@, BPF_ANY);
    }
}
