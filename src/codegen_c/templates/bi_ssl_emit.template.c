{
    __u32 _set@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_http_stash_st *_ses@E@ = bpf_map_lookup_elem(&@UNIT@_http_recv_stash, &_set@E@);
    if (_ses@E@) {
        __u64 _sssl@E@ = _ses@E@->sk, _sbuf@E@ = _ses@E@->buf;
        bpf_map_delete_elem(&@UNIT@_http_recv_stash, &_set@E@);
        if (((__s64)(__s32)(@RET@)) > 0 && _sbuf@E@) {
            struct @UNIT@_http_pending_st *_sep@E@ = bpf_map_lookup_elem(&@UNIT@_http_pending, &_sssl@E@);
            if (_sep@E@) {
                unsigned char _sresp@E@[16] = {};
                if (bpf_probe_read_user(_sresp@E@, sizeof(_sresp@E@), (void *)(unsigned long)_sbuf@E@) == 0 &&
                    _sresp@E@[0]=='H' && _sresp@E@[1]=='T' && _sresp@E@[2]=='T' && _sresp@E@[3]=='P') {
                    struct @UNIT@_http_event *_she@E@ = bpf_ringbuf_reserve(&@UNIT@_http_events, sizeof(*_she@E@), 0);
                    if (_she@E@) {
                        _she@E@->hdr.type = SPNL_EVT_USER_BASE;
                        _she@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                        _she@E@->hdr.reserved = 0;
                        _she@E@->hdr.timestamp = bpf_ktime_get_ns();
                        _she@E@->pid = _sep@E@->pid;
                        __builtin_memcpy(_she@E@->comm, _sep@E@->comm, sizeof(_she@E@->comm));
                        _she@E@->cgid = _sep@E@->cgid;
                        _she@E@->daddr = 0; _she@E@->dport = 0; _she@E@->family = 0;   /* TLS: no sock -> https + no peer */
                        _she@E@->start_ktime = _sep@E@->start_ns;
                        _she@E@->duration_ns = bpf_ktime_get_ns() - _sep@E@->start_ns;
                        __builtin_memcpy(_she@E@->req, _sep@E@->req, sizeof(_she@E@->req));
                        __builtin_memcpy(_she@E@->resp, _sresp@E@, sizeof(_she@E@->resp));
                        bpf_ringbuf_submit(_she@E@, 0);
                    }
                    bpf_map_delete_elem(&@UNIT@_http_pending, &_sssl@E@);
                }
            }
        }
    }
}
