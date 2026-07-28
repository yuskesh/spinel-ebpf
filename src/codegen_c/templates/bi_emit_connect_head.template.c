{
    struct @UNIT@_conn_event *_ce@E@ = bpf_ringbuf_reserve(&@UNIT@_conn_events, sizeof(*_ce@E@), 0);
    if (_ce@E@) {
        _ce@E@->hdr.type = SPNL_EVT_USER_BASE;
        _ce@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
        _ce@E@->hdr.reserved = 0;
        _ce@E@->hdr.timestamp = bpf_ktime_get_ns();
        _ce@E@->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_get_current_comm(_ce@E@->comm, sizeof(_ce@E@->comm));
        _ce@E@->cgid = bpf_get_current_cgroup_id();   /* k8s pod attribution (default; owner overrides below) */
