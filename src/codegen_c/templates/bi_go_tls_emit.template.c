{
    __u64 _geg@E@ = (__u64)(ctx->regs[28]);   /* arm64 g register - match the Read entry's go_tls_resp_stash */
    struct @UNIT@_http_stash_st *_ges@E@ = bpf_map_lookup_elem(&@UNIT@_go_recv_stash, &_geg@E@);
    if (_ges@E@) {
        __u64 _gesk@E@ = _ges@E@->sk, _gebuf@E@ = _ges@E@->buf;
        bpf_map_delete_elem(&@UNIT@_go_recv_stash, &_geg@E@);
        if (((__s64)(__s32)(@RET@)) > 0 && _gebuf@E@) {
            struct @UNIT@_http_pending_st *_gep@E@ = bpf_map_lookup_elem(&@UNIT@_http_pending, &_gesk@E@);
            if (_gep@E@) {
                unsigned char _geresp@E@[16] = {};
                __u64 _gern@E@ = (__u64)((__s64)(__s32)(@RET@)); if (_gern@E@ > sizeof(_geresp@E@)) _gern@E@ = sizeof(_geresp@E@);
                if (_gern@E@ >= 1 && bpf_probe_read_user(_geresp@E@, _gern@E@, (void *)(unsigned long)_gebuf@E@) == 0 &&
                    _geresp@E@[0]=='H' && _geresp@E@[1]=='T' && _geresp@E@[2]=='T' && _geresp@E@[3]=='P') {
                    struct @UNIT@_http_event *_gehe@E@ = bpf_ringbuf_reserve(&@UNIT@_http_events, sizeof(*_gehe@E@), 0);
                    if (_gehe@E@) {
                        _gehe@E@->hdr.type = SPNL_EVT_USER_BASE;
                        _gehe@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                        _gehe@E@->hdr.reserved = 0;
                        _gehe@E@->hdr.timestamp = bpf_ktime_get_ns();
                        _gehe@E@->pid = _gep@E@->pid;
                        __builtin_memcpy(_gehe@E@->comm, _gep@E@->comm, sizeof(_gehe@E@->comm));
                        _gehe@E@->cgid = _gep@E@->cgid;
                        _gehe@E@->daddr = 0; _gehe@E@->dport = 0; _gehe@E@->family = 0;   /* uprobe: no sock -> url.scheme=https */
                        _gehe@E@->start_ktime = _gep@E@->start_ns;
                        _gehe@E@->duration_ns = bpf_ktime_get_ns() - _gep@E@->start_ns;
                        __builtin_memcpy(_gehe@E@->req, _gep@E@->req, sizeof(_gehe@E@->req));
                        __builtin_memcpy(_gehe@E@->resp, _geresp@E@, sizeof(_gehe@E@->resp));
                        bpf_ringbuf_submit(_gehe@E@, 0);
                    } else spnl_lost_inc();   /* ring full -> account the dropped record */
                    bpf_map_delete_elem(&@UNIT@_http_pending, &_gesk@E@);
                }
            }
        }
    }
}
