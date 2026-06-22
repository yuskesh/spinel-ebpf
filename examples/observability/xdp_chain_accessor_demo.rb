# Per-protocol + per-source XDP packet counter, written
# entirely with chain accessors and module-style constants.
#
# Flat-name form: `p = pkt_l4_proto`, `XDP_PASS`, `IPPROTO_TCP`
# Chain form:     `p = pkt.l4.proto`, `XDP::PASS`, `IP::Proto::TCP`
#
# The generated .bpf.c is byte-identical to the flat-name form; only
# the surface syntax changes.
#
# Build:
#   spinel-ebpf compile examples/observability/xdp_chain_accessor_demo.rb \
#       -o build/xdp_chain --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/xdp_chain/xdp_chain_accessor_demo &
#   ping -c 5 -q 127.0.0.1
#   curl -s http://127.0.0.1:80   # generates TCP

@rx_total   = 0
@rx_icmp    = 0
@rx_tcp     = 0
@rx_udp     = 0
@rx_loopbk  = 0

def xdp__main
  @rx_total = @rx_total + 1

  proto = pkt.l4.proto
  if proto == IP::Proto::ICMP
    @rx_icmp = @rx_icmp + 1
  elsif proto == IP::Proto::TCP
    @rx_tcp = @rx_tcp + 1
  elsif proto == IP::Proto::UDP
    @rx_udp = @rx_udp + 1
  end

  # 127.0.0.0/8 in host byte order = 0x7f000000 / 0xff000000 mask
  if (pkt.ip4.src & 0xff000000) == 0x7f000000
    @rx_loopbk = @rx_loopbk + 1
  end

  XDP::PASS
end

puts "xdp_chain_accessor_demo loaded (SPNL_XDP_IFACE=lo)"
sleep 3600
