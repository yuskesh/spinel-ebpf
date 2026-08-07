{
    __u64 _hk@E@ = (__u64)(unsigned long)(@SK@);
    void *_hb@E@ = spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
    if (_hb@E@ && !bpf_map_lookup_elem(&@UNIT@_http_pending, &_hk@E@)) {
        struct @UNIT@_http_pending_st _hp@E@ = {};
        if (bpf_probe_read_user(_hp@E@.req, sizeof(_hp@E@.req), _hb@E@) == 0 && spnl_is_http_req(_hp@E@.req)) {
            _hp@E@.start_ns = bpf_ktime_get_ns();
            _hp@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_get_current_comm(_hp@E@.comm, sizeof(_hp@E@.comm));
            _hp@E@.cgid = bpf_get_current_cgroup_id();
            bpf_map_update_elem(&@UNIT@_http_pending, &_hk@E@, &_hp@E@, BPF_ANY);
        }
    }
}
