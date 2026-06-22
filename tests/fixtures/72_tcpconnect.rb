# outbound TCP connects (bcc tcpconnect). daddr is the __u8[4]
# tracepoint field read as a u32 (ipv4 type); on CLOSE -> SYN_SENT we emit the
# destination address + port.
def tracepoint__sock__inet_sock_set_state(daddr, dport, oldstate, newstate)
  if (oldstate == 7) && (newstate == 2)
    spnl_emit_pair(daddr, dport)
  end
  0
end
