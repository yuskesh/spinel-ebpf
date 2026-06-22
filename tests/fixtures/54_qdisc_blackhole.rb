# Ruby-written BPF qdisc — blackhole (drops every packet).
# Verifies Qdisc_ops load + tc attach + bpf_qdisc_skb_drop behavior.

class BlackHole < BPF::Qdisc
  def init(sch, opt, extack)
    qdisc_init_prologue(sch, extack)
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
    qdisc_reset_destroy_epilogue(sch)
  end

  def destroy(sch)
    qdisc_reset_destroy_epilogue(sch)
  end
end

@dropped = 0
