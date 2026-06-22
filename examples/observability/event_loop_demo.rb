# Reactor-style DSL — one module declares multiple event handlers
# via `on :<kind> do ... end`. The partition synthesizes a top-level
# `<prefix>__main` method per `on`, so the rest of the codegen pipeline
# works unchanged.
#
# This file shows a tiny "observer" that combines two event sources:
#   1. XDP hook — count every incoming packet, segregate ICMP / TCP / UDP
#   2. SOCK_OPS  — count active TCP connect events at the cgroup
#
# Build:
#   spinel-ebpf compile examples/observability/event_loop_demo.rb \
#       -o build/event_loop --build
# Run:
#   SPNL_XDP_IFACE=lo SPNL_CGROUP_PATH=/sys/fs/cgroup \
#     ./build/event_loop/event_loop_demo &
#   ping -c 5 -q 127.0.0.1
#   curl -sS http://127.0.0.1:80/ >/dev/null   # any TCP traffic
#   bpftool map dump name event_loop_dem_top_rx_total

@rx_total        = 0
@rx_icmp         = 0
@rx_tcp          = 0
@rx_udp          = 0
@active_connects = 0

module Observer
  include BPF::EventLoop

  on :xdp do
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

  on :sock_ops do
    if sock_ops_op == BPF::SockOps::TCP_CONNECT_CB
      @active_connects = @active_connects + 1
    end
  end
end

puts "event_loop_demo loaded — Observer (XDP + sock_ops via BPF::EventLoop)"
sleep 3600
