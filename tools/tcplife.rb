# tcplife — TCP session lifetimes (bcc tcplife equivalent, MVP).
#
# Hooks sock:inet_sock_set_state. The socket pointer (skaddr) keys a per-
# connection timer (lat_start/lat_end): birth on entering TCP_ESTABLISHED,
# death on *leaving* it (oldstate == ESTABLISHED). On death we stream
# (sport, dport, duration_ns). Addresses (saddr/daddr) are array fields and
# skipped in this MVP — ports + lifetime capture the core of tcplife
# (per-socket state correlation).
#
#   bin/spinel-ebpf compile tools/tcplife.rb --build -o build/tcplife
#   sudo ./build/tcplife/tcplife          # streams: <ktime> <sport> <dport> <ns>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sock__inet_sock_set_state(skaddr, oldstate, newstate, sport, dport)
  if newstate == 1            # entering TCP_ESTABLISHED -> connection birth
    lat_start(skaddr)
  end
  if oldstate == 1            # leaving TCP_ESTABLISHED -> connection death
    d = lat_end(skaddr)       # (active close goes ESTABLISHED->FIN_WAIT1, never
    if d > 0                  #  straight to TCP_CLOSE, so trigger on oldstate)
      spnl_emit3(sport, dport, d)
    end
  end
  0
end

puts "[tcplife] ktime  sport  dport  duration_ns (TCP connection lifetimes):"
Stream.spnl_stream(0)
