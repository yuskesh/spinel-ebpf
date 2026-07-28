        {   /* recover the real process by socket pointer */
            __u64 _sok@E@ = (__u64)(unsigned long)(@SKADDR@);
            struct @UNIT@_sock_owner_info *_soi@E@ = bpf_map_lookup_elem(&@UNIT@_sock_owner, &_sok@E@);
            if (_soi@E@) {
                _ce@E@->pid = _soi@E@->pid;
                __builtin_memcpy(_ce@E@->comm, _soi@E@->comm, sizeof(_ce@E@->comm));
                _ce@E@->cgid = _soi@E@->cgid;   /* recover request-initiator cgroup (softirq default was root) */
            }
        }
