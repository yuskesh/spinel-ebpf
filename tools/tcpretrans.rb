# tcpretrans — trace TCP retransmissions (bcc tcpretrans equivalent).
#
# kprobe tcp_retransmit_skb(sk, skb, segs): each call is a retransmit. We count
# them and stream the destination (daddr, dport) read from the sock via kfield
# (BPF_CORE_READ of the nested __sk_common fields). Both are network byte order.
#
#   bin/spinel-ebpf compile tools/tcpretrans.rb --build -o build/tcpretrans
#   sudo ./build/tcpretrans/tcpretrans   # streams: <ktime> <daddr_u32> <dport_be>
@retransmits = 0

module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__tcp_retransmit_skb(sk)
  @retransmits += 1
  # __sk_common is an embedded struct (same memory), so the path is one dotted
  # BPF_CORE_READ arg — comma args are pointer hops and would mis-deref it.
  daddr = kfield(sk, "sock", "__sk_common.skc_daddr")
  dport = kfield(sk, "sock", "__sk_common.skc_dport")
  spnl_emit_pair(daddr, dport)
  0
end

puts "[tcpretrans] ktime  daddr(u32)  dport(be16)  (TCP retransmits):"
Stream.spnl_stream(0)
