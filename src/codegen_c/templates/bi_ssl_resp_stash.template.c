{
    __u32 _srt@E@ = (__u32)bpf_get_current_pid_tgid();
    struct @UNIT@_http_stash_st _srs@E@ = {};
    _srs@E@.sk = (__u64)(unsigned long)(@SSL@);
    _srs@E@.buf = (__u64)(unsigned long)(@BUF@);
    bpf_map_update_elem(&@UNIT@_http_recv_stash, &_srt@E@, &_srs@E@, BPF_ANY);
}
