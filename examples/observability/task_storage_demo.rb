# Per-task local storage (TASK_STORAGE). task_incr keeps a per-task
# openat counter that persists across calls for the SAME task and is freed when
# the task exits. @max records the largest per-task count seen — a single
# process opening many files drives it far above 1, proving the value is
# task-scoped (a plain global counter could not distinguish per-task totals).
@max = 0
def kprobe__do_sys_openat2(dfd)
  n = task_incr(1)
  if n > @max
    @max = n
  end
  n
end
puts "per-task openat counter attached (TASK_STORAGE / task_incr)"
sleep 3600
