# Kernel load-check: struct_ops / TCP congestion control (kernel struct injection).
#
# A minimal TCP congestion-control algorithm registered as a struct_ops.
# Exercises struct_ops program emission and BPF_PROG-wrapped members.
# (A full Reno-like implementation lives under examples/observability/.)
def tcp_cc__init(sk)
  0
end
def tcp_cc__ssthresh(sk)
  2
end
def tcp_cc__undo_cwnd(sk)
  2
end
def tcp_cc__cong_avoid(sk, ack, acked)
  0
end
