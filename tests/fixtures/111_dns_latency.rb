# DNS request/response latency via (sock,txid) correlation on UDP :53.
# dns_req_start (udp_sendmsg) records the query start keyed by (sock<<16 | txid)
# so A+AAAA on one socket stay distinct; the response side needs an entry-stash +
# kretprobe (the response payload is only in the user buffer after the copy, like
# the tcp_recvmsg path): dns_resp_stash (udp_recvmsg entry) saves {sk, buf} by tid,
# dns_emit (udp_recvmsg return) reads the response txid, correlates, and emits one
# dns_event with duration_ns = DNS resolution RTT (QNAME echoed in the response,
# parsed in userspace). The query-only emit_dns is unchanged and coexists.
def kprobe__udp_sendmsg(sk, msg, len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568   # 0x3500 = be16 of port 53
    dns_req_start(sk, msg)
  end
  0
end

def kprobe__udp_recvmsg(sk, msg, len, flags, addr_len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568
    dns_resp_stash(sk, msg)
  end
  0
end

def kretprobe__udp_recvmsg(ret)
  dns_emit(ret)   # ret>0 guarded inside; correlates by response txid -> RTT
  0
end
