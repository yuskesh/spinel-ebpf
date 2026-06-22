# off-CPU profiler fixture.

module OffCpu
  include BPF::EventLoop

  on :tracepoint, "sched", "sched_switch" do |prev_pid, prev_state, next_pid|
    # prev going off-CPU only if state != TASK_RUNNING (0)
    if prev_state != 0
      off_cpu_start(prev_pid)
    end
    # next coming back — observe how long it was off
    off_cpu_observe(next_pid)
  end
end
