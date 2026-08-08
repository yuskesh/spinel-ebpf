# an earlier experiment Part B: the wrong destination accessor on a datagram RECV hook.
# The inverse of the send-side mistake: here `msg->msg_name` is an OUTPUT buffer
# the kernel has not written yet, so udp_dport reads uninitialised caller stack.
def kprobe__udp_recvmsg(sk, msg, len, flags, addr_len)
  if udp_dport(sk, msg) == 53
    hist_observe(1)
  end
  0
end
