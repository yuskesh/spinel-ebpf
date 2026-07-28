{
    __u64 _onow@E@ = bpf_ktime_get_ns();
    __u32 _oprev@E@ = (__u32)(@PPREV@);
    __u32 _onext@E@ = (__u32)(@PNEXT@);
    struct @UNIT@_offcpu_win *_opw@E@ = bpf_map_lookup_elem(&@UNIT@_offcpu_win, &_oprev@E@);
    if (_opw@E@ && ((__s64)(@PSTATE@)) != 0) {
        _opw@E@->sleep_ts = _onow@E@;
        _opw@E@->wait_stack = bpf_get_stackid(ctx, &bpf_stacks, 0);
    }
    struct @UNIT@_offcpu_win *_onw@E@ = bpf_map_lookup_elem(&@UNIT@_offcpu_win, &_onext@E@);
    if (_onw@E@ && _onw@E@->sleep_ts) {
        _onw@E@->offcpu_ns += _onow@E@ - _onw@E@->sleep_ts;
        _onw@E@->sleep_ts = 0;
    }
}
