# Custom CPU scheduler written in Ruby via struct_ops/sched_ext_ops.
#
# Minimal scheduler:
#   - select_cpu: always return the previous CPU (sticky placement, equivalent
#     to scx_simple's "first-fit" behaviour)
#   - enqueue: count enqueues
#   - dispatch: count dispatches
#
# The scheduler registers as `spnl_sx` (codegen-fixed). After load,
# `cat /sys/kernel/sched_ext/state` and `bpftool struct_ops list` should
# show it. To actually become the active scheduler the user has to
# enable it via the standard sched_ext sysfs (out of scope for this demo).
#
# Build:
#   spinel-ebpf compile examples/observability/sched_ext_demo.rb \
#       -o build/sched_ext_demo --build
# Run:
#   ./build/sched_ext_demo/sched_ext_demo &
#   bpftool struct_ops list
#   cat /sys/kernel/sched_ext/state  # → "disabled" until enabled

@enqueues = 0
@dispatches = 0

def sched_ext__select_cpu(p, prev_cpu, wake_flags)
  prev_cpu
end

def sched_ext__enqueue(p, enq_flags)
  @enqueues = @enqueues + 1
end

def sched_ext__dispatch(cpu, prev)
  @dispatches = @dispatches + 1
end

def sched_ext__init
  0
end

puts "spnl_sx (sched_ext_ops) loaded — see bpftool struct_ops list"
sleep 3600
