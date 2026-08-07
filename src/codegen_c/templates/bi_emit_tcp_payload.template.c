{
    struct @UNIT@_str_event *_tp@E@ = bpf_ringbuf_reserve(&@UNIT@_str_events, sizeof(*_tp@E@), 0);
    if (_tp@E@) {
        _tp@E@->hdr.type = SPNL_EVT_USER_BASE;
        _tp@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
        _tp@E@->hdr.reserved = 0;
        _tp@E@->hdr.timestamp = bpf_ktime_get_ns();
        __builtin_memset(_tp@E@->str, 0, sizeof(_tp@E@->str));
        void *_tpb@E@ = spnl_msg_ubuf((struct msghdr *)(unsigned long)(@MSG@));
        if (_tpb@E@) (void)bpf_probe_read_user(_tp@E@->str, 128, _tpb@E@);
        bpf_ringbuf_submit(_tp@E@, 0);
    } else spnl_lost_inc();   /* ring full -> account the dropped record */
}
