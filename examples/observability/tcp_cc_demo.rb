# tcp_congestion_ops written in Ruby via struct_ops.
#
# A trivial Reno-like CC that:
#   - returns a fixed ssthresh = 10
#   - returns a fixed undo_cwnd = 10
#   - keeps cong_avoid as a no-op (no cwnd math yet — Ruby/codegen needs
#     struct sock field accessors first, which is future work)
#
# The algorithm registers under the name `spnl_cc` (codegen-fixed). After
# loading you can `sysctl net.ipv4.tcp_available_congestion_control` and
# see `spnl_cc` listed, then switch a TCP socket to it via setsockopt
# (TCP_CONGESTION) or system-wide via tcp_congestion_control sysctl.
#
# Build:
#   spinel-ebpf compile examples/observability/tcp_cc_demo.rb \
#       -o build/tcp_cc_demo --build
#
# Run:
#   ./build/tcp_cc_demo/tcp_cc_demo &
#   cat /proc/sys/net/ipv4/tcp_available_congestion_control     # → ... spnl_cc
#   sysctl -w net.ipv4.tcp_congestion_control=spnl_cc
#   curl http://127.0.0.1:8080/   # uses the Ruby-defined CC

@inits = 0
@ssthresh_calls = 0
@cong_avoid_calls = 0

def tcp_cc__init(sk)
  @inits = @inits + 1
end

def tcp_cc__ssthresh(sk)
  @ssthresh_calls = @ssthresh_calls + 1
  10
end

def tcp_cc__undo_cwnd(sk)
  10
end

def tcp_cc__cong_avoid(sk, ack, acked)
  # MVP: just count. A real Reno would increment cwnd by 1/cwnd per ACK in
  # congestion avoidance and 1 per ACK in slow start, but we need struct
  # sock field accessors (tcp_sock_cwnd, tcp_sock_state, ...) — future work.
  @cong_avoid_calls = @cong_avoid_calls + 1
end

def tcp_cc__set_state(sk, new_state)
  # MVP: pass-through (need a non-empty body so partition picks the method up).
  0
end

puts "spnl_cc loaded into the kernel TCP CC registry"
sleep 3600
