{
    struct @UNIT@_dns_event *_de@E@ = bpf_ringbuf_reserve(&@UNIT@_dns_events, sizeof(*_de@E@), 0);
    if (_de@E@) {
        _de@E@->hdr.type = SPNL_EVT_USER_BASE;
        _de@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
        _de@E@->hdr.reserved = 0;
        _de@E@->hdr.timestamp = bpf_ktime_get_ns();
        _de@E@->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_get_current_comm(_de@E@->comm, sizeof(_de@E@->comm));
        _de@E@->cgid = bpf_get_current_cgroup_id();
        _de@E@->duration_ns = 0;
        __builtin_memset(_de@E@->raw, 0, sizeof(_de@E@->raw));
        void *_db@E@ = BPF_CORE_READ((struct msghdr *)(unsigned long)(@MSG@), msg_iter.__ubuf_iovec.iov_base);
        if (_db@E@) (void)bpf_probe_read_user(_de@E@->raw, sizeof(_de@E@->raw), _db@E@);
        bpf_ringbuf_submit(_de@E@, 0);
    }
}
