# A Linux CPU scheduler written in Ruby (scx_simple equivalent).
#
# A real struct_ops/sched_ext_ops attach that registers and enables a
# Ruby-written scheduler in the kernel's sched_ext subsystem.
#
# Behaviour:
#   - enqueue: put a newly runnable task onto the global DSQ
#   - dispatch: consume from the global DSQ into an idle CPU's local DSQ
#   - init: scheduler startup initialization (just returns 0 for now)
#
# Build:
#   bin/spinel-ebpf compile examples/observability/scx_simple.rb \
#                   -o build/scx --build
# Run (root required):
#   sudo ./build/scx/scx_simple &
#   # libbpf attaches struct_ops.link -> the kernel automatically enables
#   # the spnl_sx scheduler
#   cat /sys/kernel/sched_ext/state          # -> "enabled"
#   cat /sys/kernel/sched_ext/root/ops       # -> "spnl_sx"
#   # Run a workload:
#   stress-ng --cpu 8 --timeout 10
#   # Ctrl+C to stop -> libbpf destroys the link -> the kernel disables
#   # the scheduler and reverts to the built-in CFS/EEVDF

# Recent sched_ext kernels disallow dsq_move_to_local directly on
# SCX_DSQ_GLOBAL; tasks must transit through a user-created DSQ. Use
# integer 0 inline (top-level Ruby constants aren't yet supported by
# spinel-ebpf's partition).

class SimpleScx < BPF::SchedExt
  def init
    scx_create_dsq(0, -1)
    0
  end

  def enqueue(p, enq_flags)
    scx_dispatch(p, 0, SCX::SLICE_DFL, enq_flags)
  end

  def dispatch(cpu, prev)
    scx_consume(0)
  end
end

puts "scx_simple (spnl_sx) — a sched_ext scheduler written in Ruby"
puts "       cat /sys/kernel/sched_ext/state to verify it's enabled"
sleep 3600
