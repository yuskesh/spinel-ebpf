{
    __u32 _ot@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_offcpu_win *_ow@E@ = bpf_map_lookup_elem(&@UNIT@_offcpu_win, &_ot@E@);
    if (_ow@E@) {
        void *_obuf@E@ = BPF_CORE_READ((struct msghdr *)(unsigned long)(@MSG@), msg_iter.__ubuf_iovec.iov_base);
        unsigned char _oresp@E@[16] = {};
        if (_obuf@E@ && bpf_probe_read_user(_oresp@E@, sizeof(_oresp@E@), _obuf@E@) == 0 &&
            _oresp@E@[0]=='H' && _oresp@E@[1]=='T' && _oresp@E@[2]=='T' && _oresp@E@[3]=='P') {
            struct @UNIT@_offcpu_event *_oe@E@ = bpf_ringbuf_reserve(&@UNIT@_offcpu_events, sizeof(*_oe@E@), 0);
            if (_oe@E@) {
                _oe@E@->hdr.type = SPNL_EVT_USER_BASE;
                _oe@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                _oe@E@->hdr.reserved = 0;
                _oe@E@->hdr.timestamp = bpf_ktime_get_ns();
                _oe@E@->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
                bpf_get_current_comm(_oe@E@->comm, sizeof(_oe@E@->comm));
                _oe@E@->cgid = bpf_get_current_cgroup_id();
                _oe@E@->duration_ns = bpf_ktime_get_ns() - _ow@E@->start_ns;
                _oe@E@->start_ktime = _ow@E@->start_ns;
                __builtin_memcpy(_oe@E@->hdr_ext, _ow@E@->hdr_ext, sizeof(_oe@E@->hdr_ext));
                _oe@E@->offcpu_ns = _ow@E@->offcpu_ns;
                _oe@E@->wait_stack = _ow@E@->wait_stack;
                __builtin_memcpy(_oe@E@->req, _ow@E@->req, sizeof(_oe@E@->req));
                __builtin_memcpy(_oe@E@->resp, _oresp@E@, sizeof(_oe@E@->resp));
                bpf_ringbuf_submit(_oe@E@, 0);
            }
            bpf_map_delete_elem(&@UNIT@_offcpu_win, &_ot@E@);
        }
    }
}
