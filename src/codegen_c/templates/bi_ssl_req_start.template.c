{
    __u64 _sk@E@ = (__u64)(unsigned long)(@SSL@);
    void *_sb@E@ = (void *)(unsigned long)(@BUF@);
    if (_sb@E@ && !bpf_map_lookup_elem(&@UNIT@_http_pending, &_sk@E@)) {
        struct @UNIT@_http_pending_st _sp@E@ = {};
        if (bpf_probe_read_user(_sp@E@.req, sizeof(_sp@E@.req), _sb@E@) == 0 && spnl_is_http_req(_sp@E@.req)) {
            _sp@E@.start_ns = bpf_ktime_get_ns();
            _sp@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_get_current_comm(_sp@E@.comm, sizeof(_sp@E@.comm));
            _sp@E@.cgid = bpf_get_current_cgroup_id();
            bpf_map_update_elem(&@UNIT@_http_pending, &_sk@E@, &_sp@E@, BPF_ANY);
        }
    }
}
