# TCP connection lifetimes (bcc tcplife). The socket pointer
# (skaddr) keys a per-connection timer: birth on entering ESTABLISHED, death on
# leaving it. On death we emit (sport, dport, duration_ns).
def tracepoint__sock__inet_sock_set_state(skaddr, oldstate, newstate, sport, dport)
  if newstate == 1
    lat_start(skaddr)
  end
  if oldstate == 1
    d = lat_end(skaddr)
    if d > 0
      spnl_emit3(sport, dport, d)
    end
  end
  0
end
