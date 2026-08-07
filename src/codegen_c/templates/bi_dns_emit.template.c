{
    __u32 _det@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_dns_recv_stash_st *_des@E@ = bpf_map_lookup_elem(&@UNIT@_dns_recv_stash, &_det@E@);
    if (_des@E@) {
        __u64 _dsk@E@ = _des@E@->sk, _dbuf@E@ = _des@E@->buf;
        bpf_map_delete_elem(&@UNIT@_dns_recv_stash, &_det@E@);
        if (((__s64)(__s32)(@RET@)) > 0 && _dbuf@E@) {
            unsigned char _draw@E@[64] = {};
            if (bpf_probe_read_user(_draw@E@, sizeof(_draw@E@), (void *)(unsigned long)_dbuf@E@) == 0) {
                __u64 _dkey@E@ = (_dsk@E@ << 16) | ((__u64)_draw@E@[0] << 8) | (__u64)_draw@E@[1];
                __u64 *_dstart@E@ = bpf_map_lookup_elem(&@UNIT@_dns_pending, &_dkey@E@);
                if (_dstart@E@) {
                    struct @UNIT@_dns_event *_dee@E@ = bpf_ringbuf_reserve(&@UNIT@_dns_events, sizeof(*_dee@E@), 0);
                    if (_dee@E@) {
                        _dee@E@->hdr.type = SPNL_EVT_USER_BASE;
                        _dee@E@->hdr.version = SPNL_EVENT_HDR_VERSION;
                        _dee@E@->hdr.reserved = 0;
                        _dee@E@->hdr.timestamp = bpf_ktime_get_ns();
                        _dee@E@->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
                        bpf_get_current_comm(_dee@E@->comm, sizeof(_dee@E@->comm));
                        _dee@E@->cgid = bpf_get_current_cgroup_id();
                        __builtin_memcpy(_dee@E@->raw, _draw@E@, sizeof(_dee@E@->raw));
                        _dee@E@->duration_ns = bpf_ktime_get_ns() - *_dstart@E@;
                        _dee@E@->raw_status = 0;   /* this path only reserves after a read that returned 0 */
                        bpf_ringbuf_submit(_dee@E@, 0);
                    } else spnl_lost_inc();   /* ring full -> account the dropped record */
                    bpf_map_delete_elem(&@UNIT@_dns_pending, &_dkey@E@);
                }
            }
        }
    }
}
