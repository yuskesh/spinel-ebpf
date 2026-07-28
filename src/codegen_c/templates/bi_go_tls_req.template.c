{
    __u64 _grk@E@ = (__u64)(unsigned long)(@CONN@);
    void *_grb@E@ = (void *)(unsigned long)(@PTR@);
    __u64 _grn@E@ = (__u64)(@LEN@);
    if (_grn@E@ > sizeof(((struct @UNIT@_http_pending_st *)0)->req)) _grn@E@ = sizeof(((struct @UNIT@_http_pending_st *)0)->req);
    if (_grb@E@ && _grn@E@ >= 4 && !bpf_map_lookup_elem(&@UNIT@_http_pending, &_grk@E@)) {
        struct @UNIT@_http_pending_st _grp@E@ = {};
        if (bpf_probe_read_user(_grp@E@.req, _grn@E@, _grb@E@) == 0 && spnl_is_http_req(_grp@E@.req)) {
            _grp@E@.start_ns = bpf_ktime_get_ns();
            _grp@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_get_current_comm(_grp@E@.comm, sizeof(_grp@E@.comm));
            _grp@E@.cgid = bpf_get_current_cgroup_id();
            bpf_map_update_elem(&@UNIT@_http_pending, &_grk@E@, &_grp@E@, BPF_ANY);
        }
    }
}
