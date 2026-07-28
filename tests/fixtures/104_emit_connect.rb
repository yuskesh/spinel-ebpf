# emit_connect -- pack one TCP socket-state event (process + remote + srtt) into
# one ringbuf record. A single `inet_sock_set_state` tracepoint fire carries all fields
# atomically, so unlike three separate string emits there is no desync. srtt_us is read from
# tcp_sock via CO-RE (untrusted skaddr -> BPF_CORE_READ).
#
# 8 params (skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
# far exceed BPF's 5 arg-registers, so the wrapper->inner boundary uses the caps
# struct. oldstate lets userspace derive direction (active/passive); daddr6_hi/lo carry
# the IPv6 peer (used when family==AF_INET6). Filter on newstate==ESTABLISHED.
def tracepoint__sock__inet_sock_set_state(skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
  if newstate == 1   # TCP_ESTABLISHED
    emit_connect(skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)
  end
  0
end
