# emit_tcp_payload -- generic L7 send-buffer capture from tcp_sendmsg.
# TCP sibling of emit_dns: the kernel is protocol-agnostic (it just copies the
# first 128 bytes of the send buffer into the str ringbuf), and the userspace side parses
# the L7 protocol (e.g. Redis RESP). Reuses the str_events ringbuf + spnl_stream print.
def kprobe__tcp_sendmsg(sk, msg, size)
  emit_tcp_payload(msg)
end
