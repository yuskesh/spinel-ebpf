# IPv6 packet header builtin smoke fixture.
# An xdp handler counting IPv6 ICMPv6 packets (proto=58) and stashing
# the upper 64 bits of the source address.

@v6_pkts = 0
@last_src_hi = 0

def xdp__main
  proto = pkt_l4_proto
  if proto == 58
    @v6_pkts += 1
    @last_src_hi = pkt_ip6_src_hi
  end
  2
end
