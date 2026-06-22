# tcpaccept — trace inbound (passive) TCP connections (bcc tcpaccept equivalent).
#
# A server's accepted socket transitions SYN_RECV -> ESTABLISHED. At that point
# sport is the local (listening) port and daddr is the remote client's IPv4.
# We emit (sport, daddr) — the accepting endpoint + the client address.
#
#   bin/spinel-ebpf compile tools/tcpaccept.rb --build -o build/tcpaccept
#   sudo ./build/tcpaccept/tcpaccept     # streams: <ktime> <lport> <raddr_u32>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sock__inet_sock_set_state(daddr, sport, oldstate, newstate)
  if (oldstate == 3) && (newstate == 1)   # TCP_SYN_RECV -> TCP_ESTABLISHED = passive open
    spnl_emit_pair(sport, daddr)
  end
  0
end

puts "[tcpaccept] ktime  lport  raddr(u32, net-order) (inbound connects):"
Stream.spnl_stream(0)
