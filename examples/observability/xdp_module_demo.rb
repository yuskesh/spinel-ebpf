# Per-protocol XDP counter written with module + include.
#
# Same logic as xdp_class_demo.rb and xdp_chain_accessor_demo.rb,
# only the namespace declaration changes:
#
#   class ProtoCounter < BPF::XDP    →    module ProtoCounter; include BPF::XDP; end
#
# `module` is the right Ruby tool here because the namespace is never
# instantiated — there's no `.new`, no instance state, no inheritance
# chain to traverse. Just a container for the XDP entry point.
#
# Build:
#   spinel-ebpf compile examples/observability/xdp_module_demo.rb \
#       -o build/xdp_module --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/xdp_module/xdp_module_demo &
#   ping -c 5 -q 127.0.0.1

@rx_total = 0
@rx_icmp  = 0
@rx_tcp   = 0
@rx_udp   = 0

module ProtoCounter
  include BPF::XDP

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

puts "xdp_module_demo loaded (module ProtoCounter ; include BPF::XDP)"
sleep 3600
