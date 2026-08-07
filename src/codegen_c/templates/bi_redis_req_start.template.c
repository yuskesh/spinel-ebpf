{
    __u64 _dk@E@ = (__u64)(unsigned long)(@SK@);
    void *_db@E@ = spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
    __u64 _dn@E@ = (__u64)(@SIZE@);
    if (_dn@E@ > sizeof(((struct @UNIT@_redis_pending_st *)0)->req)) _dn@E@ = sizeof(((struct @UNIT@_redis_pending_st *)0)->req);
    if (_db@E@ && _dn@E@ >= 2 && !bpf_map_lookup_elem(&@UNIT@_redis_pending, &_dk@E@)) {
        struct @UNIT@_redis_pending_st _dp@E@ = {};
        if (bpf_probe_read_user(_dp@E@.req, _dn@E@, _db@E@) == 0 && spnl_is_redis_cmd(_dp@E@.req)) {
            _dp@E@.start_ns = bpf_ktime_get_ns();
            _dp@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_get_current_comm(_dp@E@.comm, sizeof(_dp@E@.comm));
            _dp@E@.cgid = bpf_get_current_cgroup_id();
            bpf_map_update_elem(&@UNIT@_redis_pending, &_dk@E@, &_dp@E@, BPF_ANY);
        }
    }
}
