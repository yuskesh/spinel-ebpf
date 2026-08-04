{
    __u32 _et@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_redis_stash_st *_es@E@ = bpf_map_lookup_elem(&@UNIT@_redis_recv_stash, &_et@E@);
    if (_es@E@) {
        __u64 _esk@E@ = _es@E@->sk, _ebuf@E@ = _es@E@->buf;
        bpf_map_delete_elem(&@UNIT@_redis_recv_stash, &_et@E@);
        if (((__s64)(__s32)(@RET@)) > 0 && _ebuf@E@) {
            struct @UNIT@_redis_pending_st *_ep@E@ = bpf_map_lookup_elem(&@UNIT@_redis_pending, &_esk@E@);
            if (_ep@E@) {
                unsigned char _resp@E@[16] = {};
                __u64 _rn@E@ = (__u64)((__s64)(__s32)(@RET@)); if (_rn@E@ > sizeof(_resp@E@)) _rn@E@ = sizeof(_resp@E@);
                if (_rn@E@ >= 1 && bpf_probe_read_user(_resp@E@, _rn@E@, (void *)(unsigned long)_ebuf@E@) == 0 &&
                    (_resp@E@[0]=='+' || _resp@E@[0]=='-' || _resp@E@[0]==':' || _resp@E@[0]=='$' || _resp@E@[0]=='*')) {
                    struct @UNIT@_redis_event *_he@E@ = bpf_ringbuf_reserve(&@UNIT@_redis_events, sizeof(*_he@E@), 0);
                    if (_he@E@) {
                        _he@E@->hdr.type = SPNL_EVT_USER_BASE;
                        _he@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                        _he@E@->hdr.reserved = 0;
                        _he@E@->hdr.timestamp = bpf_ktime_get_ns();
                        _he@E@->pid = _ep@E@->pid;
                        __builtin_memcpy(_he@E@->comm, _ep@E@->comm, sizeof(_he@E@->comm));
                        _he@E@->cgid = _ep@E@->cgid;
                        _he@E@->daddr = BPF_CORE_READ((struct sock *)(unsigned long)_esk@E@, __sk_common.skc_daddr);
                        _he@E@->dport = bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)_esk@E@, __sk_common.skc_dport));
                        _he@E@->family = (__u16)BPF_CORE_READ((struct sock *)(unsigned long)_esk@E@, __sk_common.skc_family);
                        _he@E@->start_ktime = _ep@E@->start_ns;
                        _he@E@->duration_ns = bpf_ktime_get_ns() - _ep@E@->start_ns;
                        __builtin_memcpy(_he@E@->req, _ep@E@->req, sizeof(_he@E@->req));
                        __builtin_memcpy(_he@E@->resp, _resp@E@, sizeof(_he@E@->resp));
                        bpf_ringbuf_submit(_he@E@, 0);
                    } else spnl_lost_inc();   /* ring full -> account the dropped record */
                    bpf_map_delete_elem(&@UNIT@_redis_pending, &_esk@E@);
                }
            }
        }
    }
}
