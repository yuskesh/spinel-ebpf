{
    __u64 _rsk@E@ = (__u64)(unsigned long)(@SK@);
    struct @UNIT@_req_state *_rex@E@ = bpf_map_lookup_elem(&@UNIT@_req_start, &_rsk@E@);
    if (_rex@E@) {
        _rex@E@->outstanding += 1;
        _rex@E@->mux = 1;
    } else {
        struct @UNIT@_req_state _rst@E@ = {};
        _rst@E@.start_ns = bpf_ktime_get_ns();
        _rst@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_get_current_comm(_rst@E@.comm, sizeof(_rst@E@.comm));
        _rst@E@.cgid = bpf_get_current_cgroup_id();
        _rst@E@.outstanding = 1;
        bpf_map_update_elem(&@UNIT@_req_start, &_rsk@E@, &_rst@E@, BPF_ANY);
    }
}
