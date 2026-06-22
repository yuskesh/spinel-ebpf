# IPv6 packet header accessor demo.
#
# Counts IPv6 packets on the attach interface and breaks them down by
# L4 protocol. ICMPv6 (proto=58), TCP (6) and UDP (17) are categorized;
# anything else (including extension headers like Hop-by-Hop=0) lands
# in `rx_v6_other`. Also stashes the upper 64 bits of the source
# address into a per-unit map for cross-reference with bpftool.
#
# Build (inside the project's debian:trixie build container):
#   container exec <build> bash -c "cd /work && \
#       bin/spinel-ebpf compile examples/observability/xdp_ipv6_demo.rb \
#                       -o build/xdp_ipv6 --build"
#
# Run + exercise:
#   SPNL_XDP_IFACE=lo ./build/xdp_ipv6/xdp_ipv6_demo &
#   ping6 -c 5 -q ::1
#   curl -s "http://[::1]:80" 2>/dev/null || true
#
# Read counters:
#   bpftool map dump name xdp_ipv6_demo_top_rx_v6_total
#   bpftool map dump name xdp_ipv6_demo_top_rx_v6_icmp6
#   bpftool map dump name xdp_ipv6_demo_top_last_src_hi

@rx_v6_total = 0
@rx_v6_icmp6 = 0
@rx_v6_tcp   = 0
@rx_v6_udp   = 0
@rx_v6_other = 0
@last_src_hi = 0

def xdp__main
  proto_v4 = pkt.l4.proto
  # pkt_l4_proto returns the IPv6 nexthdr too — but a non-zero value
  # could also be an IPv4 protocol. Distinguish using EtherType
  # implicitly: pkt_ip6_src_hi returns 0 unless the frame is IPv6.
  src_hi = pkt.ip6.src_hi
  if src_hi != 0 || proto_v4 == 58
    @rx_v6_total = @rx_v6_total + 1
    @last_src_hi = src_hi

    if proto_v4 == 58
      @rx_v6_icmp6 = @rx_v6_icmp6 + 1
    elsif proto_v4 == 6
      @rx_v6_tcp = @rx_v6_tcp + 1
    elsif proto_v4 == 17
      @rx_v6_udp = @rx_v6_udp + 1
    else
      @rx_v6_other = @rx_v6_other + 1
    end
  end

  XDP::PASS
end

puts "xdp_ipv6_demo loaded (SPNL_XDP_IFACE=lo) — exercise with ping6 ::1"
sleep 3600
