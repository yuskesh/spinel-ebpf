# A real FIFO BPF qdisc. Actually queues + dequeues packets using
# bpf_list + bpf_obj_new + kptr_xchg.

class FifoQdisc < BPF::Qdisc
  def init(sch, opt, extack)
    0
  end

  def enqueue(skb, sch, to_free)
    @enqueued = @enqueued + 1
    queue_push(skb, to_free)
  end

  def dequeue(sch)
    @dequeued = @dequeued + 1
    skb = queue_pop
    if skb != 0
      qdisc_bstats_update(sch, skb)
    end
    skb
  end

  def reset(sch)
    0
  end

  def destroy(sch)
    0
  end
end

@enqueued = 0
@dequeued = 0
