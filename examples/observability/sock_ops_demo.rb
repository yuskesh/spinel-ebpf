# BPF_PROG_TYPE_SOCK_OPS for TCP socket state observation. The
# kernel TCP stack invokes this callback at well-defined state-transition
# points (connect / established / state change / ...). Each event sets
# `ctx->op` to one of the BPF_SOCK_OPS_* enum values, and for STATE_CB
# `ctx->args[1]` carries the new TCP state code (TCP_STATE_*).
#
# Counts:
#   - active connects (TCP_CONNECT_CB)
#   - passive established (PASSIVE_ESTABLISHED_CB)
#   - FIN_WAIT1 transitions (state cb where new state = 4)
#   - CLOSE transitions (state cb where new state = 7)
#
# Attach:
#   This is a SEC("sockops") program. Attach is cgroup-scoped:
#     bpftool cgroup attach /sys/fs/cgroup sock_ops <pinned-prog>
#
# Build:
#   spinel-ebpf compile examples/observability/sock_ops_demo.rb \
#       -o build/sock_ops_demo --build
#
# Run (manual attach for the demo):
#   ./build/sock_ops_demo/sock_ops_demo &
#   bpftool prog show
#   bpftool prog pin id <SOP_ID> /sys/fs/bpf/sock_ops
#   bpftool cgroup attach /sys/fs/cgroup sock_ops pinned /sys/fs/bpf/sock_ops
#   # generate TCP traffic; counters in @* ivars will increment

@active_connects = 0
@passive_established = 0
@fin_wait1_transitions = 0
@close_transitions = 0

def sock_ops__main
  op = sock_ops_op
  if op == BPF::SockOps::TCP_CONNECT_CB
    @active_connects = @active_connects + 1
  elsif op == BPF::SockOps::PASSIVE_ESTABLISHED_CB
    @passive_established = @passive_established + 1
  elsif op == BPF::SockOps::STATE_CB
    new_state = sock_ops_state
    if new_state == TCP::State::FIN_WAIT1
      @fin_wait1_transitions = @fin_wait1_transitions + 1
    elsif new_state == TCP::State::CLOSE
      @close_transitions = @close_transitions + 1
    end
  end
end

puts "sock_ops loaded. Attach via bpftool cgroup attach to start observing."
sleep 3600
