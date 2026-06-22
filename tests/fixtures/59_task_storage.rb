# per-task local storage (TASK_STORAGE). Tracks a per-task openat counter
# that persists across kprobe calls for the same task and is freed when the
# task exits. @max (a shared HASH ivar) records the largest per-task count seen.
@max = 0

def kprobe__do_sys_openat2(dfd)
  n = task_incr(1)
  if n > @max
    @max = n
  end
  n
end
