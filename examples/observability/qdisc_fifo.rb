# A real FIFO BPF qdisc — packets are actually queued + dequeued via bpf_list.
#
# The blackhole qdisc dropped every packet; this one, behind the queue_push /
# queue_pop builtins:
#   - allocates a wrapper struct with bpf_obj_new
#   - safely transfers ownership of the skb with bpf_kptr_xchg
#   - does bpf_list_push_back / bpf_list_pop_front under bpf_spin_lock
#   - returns the wrapper with bpf_obj_drop
# so packets are correctly passed on to the kernel network stack.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/qdisc_fifo.rb \
#                   -o build/qf --build
# Run:
#   ./build/qf/qdisc_fifo &
#   tc qdisc add dev lo root handle 1: spnl_qdisc
#   ping -c 5 127.0.0.1                     # 5 packets all pass through!
#   tc -s qdisc show dev lo                  # Sent X bytes Y pkt (dropped 0)
#   bpftool map dump name <enqueued/dequeued>

class FifoQdisc < BPF::Qdisc
  def init(sch, opt, extack)
    0
  end

  def enqueue(skb, sch, to_free)
    @enqueued = @enqueued + 1
    queue_push(skb, to_free)  # NET_XMIT_SUCCESS (0) or NET_XMIT_DROP (1)
  end

  def dequeue(sch)
    @dequeued = @dequeued + 1
    skb = queue_pop  # struct sk_buff * (cast to __s64; 0 = NULL = queue empty)
    if skb != 0
      # Update Qdisc bstats so `tc -s qdisc show` reports accurate
      # Sent bytes / packets counts (instead of always 0).
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

puts "qdisc_fifo (spnl_qdisc) loaded — actual FIFO queue, not blackhole"
puts "       tc qdisc add dev <iface> root handle 1: spnl_qdisc"
sleep 3600
