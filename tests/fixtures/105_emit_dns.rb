# emit_dns -- resolver-independent DNS query capture from udp_sendmsg (socket :53).
# Filter to :53 via kfield(sk, ...skc_dport). emit_dns copies the raw DNS payload
# (header + QNAME) into one record; the length-prefixed QNAME is converted to dotted
# host in userspace (an in-kernel label walk explodes verifier state). Unlike the libc
# getaddrinfo uprobe, this catches Go native / musl / any resolver.
def kprobe__udp_sendmsg(sk, msg, len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568   # 0x3500 = be16 of port 53
    emit_dns(msg)
  end
  0
end
