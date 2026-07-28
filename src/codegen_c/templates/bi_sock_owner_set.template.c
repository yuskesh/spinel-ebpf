{
    __u64 _sok@E@ = (__u64)(unsigned long)(@SK@);
    struct @UNIT@_sock_owner_info _soi@E@ = {};
    _soi@E@.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(_soi@E@.comm, sizeof(_soi@E@.comm));
    _soi@E@.cgid = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&@UNIT@_sock_owner, &_sok@E@, &_soi@E@, BPF_ANY);
}
