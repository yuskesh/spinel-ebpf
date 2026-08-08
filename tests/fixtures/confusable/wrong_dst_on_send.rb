# an earlier experiment Part B: the wrong destination accessor on a datagram SEND hook.
def kprobe__udp_sendmsg(sk, msg, len)
  if sock_dport(sk) == 53
    emit_dns(msg)
  end
  0
end
