{
    struct @UNIT@_l7stream_event *_ls@E@ = bpf_ringbuf_reserve(&@UNIT@_l7stream_events, sizeof(*_ls@E@), 0);
    if (_ls@E@) {
        _ls@E@->hdr.type = SPNL_EVT_USER_BASE;
        _ls@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
        _ls@E@->hdr.reserved = 0;
        _ls@E@->hdr.timestamp = bpf_ktime_get_ns();
        _ls@E@->sock = (__u64)(unsigned long)(@SK@);
        __u64 _ln@E@ = (__u64)(@SIZE@);
        if (_ln@E@ > 128) _ln@E@ = 128;   /* cap: proven [0,128] bound for bpf_probe_read_user (dst = raw[128]) */
        _ls@E@->len = (__u32)_ln@E@;
        __builtin_memset(_ls@E@->raw, 0, sizeof(_ls@E@->raw));
        void *_lb@E@ = spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
        if (_lb@E@ && _ln@E@) (void)bpf_probe_read_user(_ls@E@->raw, _ln@E@, _lb@E@);   /* len == bytes copied, byte-exact up to 128 */
        bpf_ringbuf_submit(_ls@E@, 0);
    } else spnl_lost_inc();   /* ring full -> account the dropped record */
}
