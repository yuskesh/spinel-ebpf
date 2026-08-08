# an earlier experiment Part B, the two-sided control: the SAME pair of hooks, each side spelled
# the way its direction requires. The gate must let this through -- a latency
# probe needs udp_dport on the send side and sock_dport on the receive side, so a
# rule that refused either name outright would refuse the correct program too.
def kprobe__udp_sendmsg(sk, msg, len)
  if udp_dport(sk, msg) == 53
    dns_req_start(sk, msg)
  end
  0
end

def kprobe__udp_recvmsg(sk, msg, len, flags, addr_len)
  if sock_dport(sk) == 53
    dns_resp_stash(sk, msg)
  end
  0
end

def kretprobe__udp_recvmsg(ret)
  dns_emit(ret)
  0
end
