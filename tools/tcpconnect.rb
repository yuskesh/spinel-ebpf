# tcpconnect — trace outbound TCP connections (bcc tcpconnect equivalent).
#
# sock:inet_sock_set_state fires CLOSE -> SYN_SENT when a socket starts an
# active connect; at that point the destination is set. We emit the dest IPv4
# (daddr, read from the __u8[4] tracepoint field as a u32, network byte order)
# and the dest port. bcc tcpconnect reports the same (active opens).
#
#   bin/spinel-ebpf compile tools/tcpconnect.rb --build -o build/tcpconnect
#   sudo ./build/tcpconnect/tcpconnect    # streams: <ktime> <daddr_u32> <dport>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sock__inet_sock_set_state(daddr, dport, oldstate, newstate)
  if (oldstate == 7) && (newstate == 2)   # TCP_CLOSE -> TCP_SYN_SENT = active open
    spnl_emit_pair(daddr, dport)
  end
  0
end

puts "[tcpconnect] ktime  daddr(u32, net-order)  dport (outbound connects):"
Stream.spnl_stream(0)
