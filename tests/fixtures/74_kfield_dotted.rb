# kfield embedded-struct dotted path. __sk_common is an embedded
# struct in struct sock, so the field is a single dotted BPF_CORE_READ arg
# (comma args are pointer hops). Used by tcpretrans to read the dest addr/port.
def kprobe__tcp_sendmsg(sk)
  daddr = kfield(sk, "sock", "__sk_common.skc_daddr")
  dport = kfield(sk, "sock", "__sk_common.skc_dport")
  spnl_emit_pair(daddr, dport)
  0
end
