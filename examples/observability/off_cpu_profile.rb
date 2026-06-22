# Off-CPU profiler (equivalent to bcc offcputime.py).
#
# Hook sched:sched_switch. When a task goes off-CPU (prev_state != 0, i.e.
# voluntary sleep — I/O wait, lock wait, sleep(), etc.), record its kernel
# stack and entry time. When it comes back on-CPU, compute the time spent
# off and bin (stack_id -> total off-CPU ns) in bpf_hist_keyed.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/off_cpu_profile.rb \
#                   -o build/offcpu --build
# Run:
#   ./build/offcpu/off_cpu_profile &
#   # exercise (mix of sleep + I/O):
#   (sleep 1; sleep 2; cat /etc/hostname > /dev/null; sleep 1) &
#   ...
#
# Then use the profile.py post-processor (or your own) to rank
# bpf_hist_keyed by stack_id and symbolize via /proc/kallsyms.

module OffCpuProfile
  include BPF::EventLoop

  on :tracepoint, "sched", "sched_switch" do |prev_pid, prev_state, next_pid|
    # prev voluntarily going off-CPU (preempt-then-resume produces
    # prev_state == 0 which we want to skip — it isn't real off-CPU).
    if prev_state != 0
      off_cpu_start(prev_pid)
    end
    # next coming back from off-CPU — credits its off-CPU stack with
    # the time delta in the keyed log2 hist.
    off_cpu_observe(next_pid)
  end
end

puts "off_cpu_profile loaded — exercise voluntary sleeps then dump bpf_hist_keyed + bpf_stacks"
sleep 3600
