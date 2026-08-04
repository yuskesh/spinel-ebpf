{
    __u64 _lsk@E@ = (__u64)(unsigned long)(@SK@);
    struct @UNIT@_req_state *_lst@E@ = bpf_map_lookup_elem(&@UNIT@_req_start, &_lsk@E@);
    if (_lst@E@) {
        if (_lst@E@->mux) {
            if (_lst@E@->outstanding > 0) _lst@E@->outstanding -= 1;
        } else {
            struct @UNIT@_l7_event *_le@E@ = bpf_ringbuf_reserve(&@UNIT@_l7_events, sizeof(*_le@E@), 0);
            if (_le@E@) {
                _le@E@->hdr.type = SPNL_EVT_USER_BASE;
                _le@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                _le@E@->hdr.reserved = 0;
                _le@E@->hdr.timestamp = bpf_ktime_get_ns();
                _le@E@->pid = _lst@E@->pid;
                __builtin_memcpy(_le@E@->comm, _lst@E@->comm, sizeof(_le@E@->comm));
                _le@E@->cgid = _lst@E@->cgid;
                _le@E@->daddr = BPF_CORE_READ((struct sock *)(unsigned long)(@SK@), __sk_common.skc_daddr);
                _le@E@->dport = bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)(@SK@), __sk_common.skc_dport));
                _le@E@->family = (__u16)BPF_CORE_READ((struct sock *)(unsigned long)(@SK@), __sk_common.skc_family);
                _le@E@->start_ktime = _lst@E@->start_ns;
                _le@E@->duration_ns = bpf_ktime_get_ns() - _lst@E@->start_ns;
                bpf_ringbuf_submit(_le@E@, 0);
            } else spnl_lost_inc();   /* ring full -> account the dropped record */
            bpf_map_delete_elem(&@UNIT@_req_start, &_lsk@E@);
        }
    }
}
