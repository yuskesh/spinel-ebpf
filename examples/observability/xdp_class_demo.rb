# Per-protocol XDP counter written with `class MyXDP < BPF::XDP`.
# Equivalent to xdp_chain_accessor_demo.rb (which used `def xdp__main`),
# only the surface form changes.
#
# Build:
#   spinel-ebpf compile examples/observability/xdp_class_demo.rb \
#       -o build/xdp_class --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/xdp_class/xdp_class_demo &
#   ping -c 5 -q 127.0.0.1

@rx_total = 0
@rx_icmp  = 0
@rx_tcp   = 0
@rx_udp   = 0

class ProtoCounter < BPF::XDP
  def main
    @rx_total = @rx_total + 1

    proto = pkt.l4.proto
    if proto == IP::Proto::ICMP
      @rx_icmp = @rx_icmp + 1
    elsif proto == IP::Proto::TCP
      @rx_tcp = @rx_tcp + 1
    elsif proto == IP::Proto::UDP
      @rx_udp = @rx_udp + 1
    end

    XDP::PASS
  end
end

puts "xdp_class_demo loaded (ProtoCounter < BPF::XDP)"
sleep 3600
