{
    __u32 _ot@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_offcpu_stash_st *_os@E@ = bpf_map_lookup_elem(&@UNIT@_offcpu_stash, &_ot@E@);
    if (_os@E@) {
        __u64 _obuf@E@ = _os@E@->buf;
        bpf_map_delete_elem(&@UNIT@_offcpu_stash, &_ot@E@);
        if (((__s64)(__s32)(@RET@)) > 0 && _obuf@E@) {
            struct @UNIT@_offcpu_win _ow@E@ = {};
            if (bpf_probe_read_user(_ow@E@.req, sizeof(_ow@E@.req), (void *)(unsigned long)_obuf@E@) == 0 && spnl_is_http_req(_ow@E@.req)) {
                bpf_probe_read_user(_ow@E@.hdr_ext, sizeof(_ow@E@.hdr_ext), (void *)(unsigned long)_obuf@E@);
                _ow@E@.start_ns = bpf_ktime_get_ns();
                _ow@E@.wait_stack = -1;
                bpf_map_update_elem(&@UNIT@_offcpu_win, &_ot@E@, &_ow@E@, BPF_ANY);
            }
        }
    }
}
