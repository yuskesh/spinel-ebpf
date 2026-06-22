# A BPF qdisc written in Ruby — a blackhole (drops every packet).
#
# Behaviour: enqueue routes every packet through bpf_qdisc_skb_drop to drop it
# immediately, and dequeue returns NULL. Attached to an interface via tc, every
# packet through that interface vanishes (= ping 100% loss).
#
# Build:
#   bin/spinel-ebpf compile examples/observability/qdisc_blackhole.rb \
#                   -o build/qd --build
# Run:
#   ./build/qd/qdisc_blackhole &
#   bpftool struct_ops list           # spnl_qdisc shows up
#   ip link add dummy0 type dummy && ip link set dummy0 up
#   tc qdisc add dev dummy0 root handle 1: spnl_qdisc
#   ping -I dummy0 -c 5 192.0.2.1     # 100% loss (qdisc drops everything)
#   bpftool map dump name qdisc_blackh_top_dropped  # @dropped increments

class BlackHole < BPF::Qdisc
  # enqueue MUST release the skb reference (via bpf_qdisc_skb_drop)
  # — without it the verifier refuses the program with "Unreleased
  # reference … leads to reference leak". init/reset/destroy stay
  # body-empty (init_prologue / reset_destroy_epilogue are kfuncs that
  # the verifier flags as "not allowed" from this struct_ops member —
  # they're recommended for tracking stats but optional for liveness).
  def init(sch, opt, extack)
    0
  end

  def enqueue(skb, sch, to_free)
    @dropped = @dropped + 1
    qdisc_skb_drop(skb, to_free)
    1  # NET_XMIT_DROP
  end

  def dequeue(sch)
    0  # NULL — queue is always empty
  end

  def reset(sch)
    0
  end

  def destroy(sch)
    0
  end
end

@dropped = 0

puts "qdisc_blackhole (spnl_qdisc) loaded"
puts "       tc qdisc add dev <iface> root handle 1: spnl_qdisc"
sleep 3600
