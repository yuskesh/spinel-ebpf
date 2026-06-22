# tcpstates — trace every TCP state transition (bcc tcpstates equivalent).
#
# sock:inet_sock_set_state fires on each state change; we stream
# (oldstate, newstate, sport, dport). State numbers are the kernel tcp_states
# enum: 1=ESTABLISHED 2=SYN_SENT 3=SYN_RECV 4=FIN_WAIT1 5=FIN_WAIT2 6=TIME_WAIT
# 7=CLOSE 8=CLOSE_WAIT 9=LAST_ACK 10=LISTEN 11=CLOSING.
#
#   bin/spinel-ebpf compile tools/tcpstates.rb --build -o build/tcpstates
#   sudo ./build/tcpstates/tcpstates   # streams: <ktime> <old> <new> <sport> <dport>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sock__inet_sock_set_state(oldstate, newstate, sport, dport)
  spnl_emit4(oldstate, newstate, sport, dport)
  0
end

puts "[tcpstates] ktime  old  new  sport  dport (TCP state transitions):"
Stream.spnl_stream(0)
