# Per-protocol XDP counter.
#
# Splits the rx counter by L4 protocol using pkt_l4_proto and KNOWN_CONSTANTS
# comparison. Demonstrates that a single Ruby handler can classify packets at
# the XDP hook with zero userspace context switches.

XDP_PASS     = 2
IPPROTO_ICMP = 1
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17

@rx_icmp  = 0
@rx_tcp   = 0
@rx_udp   = 0
@rx_other = 0

def xdp__main
  p = pkt_l4_proto
  if p == IPPROTO_ICMP
    @rx_icmp = @rx_icmp + 1
  elsif p == IPPROTO_TCP
    @rx_tcp = @rx_tcp + 1
  elsif p == IPPROTO_UDP
    @rx_udp = @rx_udp + 1
  else
    @rx_other = @rx_other + 1
  end
  XDP_PASS
end

puts "[demo] XDP per-protocol counter attached. sleeping 15s; dump 4 counters via bpftool."
sleep 15
puts "[demo] exiting."
