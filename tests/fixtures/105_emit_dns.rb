# emit_dns -- resolver-independent DNS query capture from udp_sendmsg.
#
# `udp_dport(sk, msg)` is the destination of THIS datagram, which is where an
# unconnected sender puts it. The socket's own skc_dport is 0 for such a sender,
# so the older spellings of this filter -- kfield(sk, "sock",
# "__sk_common.skc_dport") == 13568, and sock_dport(sk) == 53 -- both silently
# reported nothing for, e.g., a dnsmasq forwarding upstream.
#
# emit_dns copies the raw DNS payload (header + QNAME) into one record; the
# length-prefixed QNAME is converted to a dotted host in userspace (an in-kernel
# label walk explodes verifier state). Both halves go through spnl_msg_ubuf, so
# a multi-iovec sendmsg reads the payload rather than a kernel pointer.
def kprobe__udp_sendmsg(sk, msg, len)
  if udp_dport(sk, msg) == 53
    emit_dns(msg)
  end
  0
end
