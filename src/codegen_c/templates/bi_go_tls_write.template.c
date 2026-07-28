{
    void *_gp@E@ = (void *)(unsigned long)(@PTR@);
    __u64 _gn@E@ = (__u64)(@LEN@);
    if (_gn@E@ > 64) _gn@E@ = 64;   /* bound to the Go slice len (a fixed read -EFAULTs past a short buffer) */
    if (_gp@E@ && _gn@E@ >= 4) {
        unsigned char _greq@E@[64] = {};
        if (bpf_probe_read_user(_greq@E@, _gn@E@, _gp@E@) == 0 && spnl_is_http_req(_greq@E@)) {
            struct @UNIT@_http_event *_he@E@ = bpf_ringbuf_reserve(&@UNIT@_http_events, sizeof(*_he@E@), 0);
            if (_he@E@) {
                _he@E@->hdr.type = SPNL_EVT_USER_BASE;
                _he@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                _he@E@->hdr.reserved = 0;
                _he@E@->hdr.timestamp = bpf_ktime_get_ns();
                _he@E@->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
                bpf_get_current_comm(_he@E@->comm, sizeof(_he@E@->comm));
                _he@E@->cgid = bpf_get_current_cgroup_id();
                _he@E@->daddr = 0;   /* a uprobe context has no socket, so userspace marks url.scheme=https */
                _he@E@->dport = 0;
                _he@E@->family = 0;
                _he@E@->start_ktime = _he@E@->hdr.timestamp;
                _he@E@->duration_ns = 0;   /* request-only; status/duration arrive with (*Conn).Read */
                __builtin_memcpy(_he@E@->req, _greq@E@, sizeof(_he@E@->req));
                __builtin_memset(_he@E@->resp, 0, sizeof(_he@E@->resp));
                bpf_ringbuf_submit(_he@E@, 0);
            }
        }
    }
}
