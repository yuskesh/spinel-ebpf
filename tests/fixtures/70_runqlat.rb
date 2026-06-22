# run-queue latency (bcc runqlat). lat_start keyed by the woken
# pid on sched_wakeup; lat_end on sched_switch for the task picked to run next
# yields the wakeup->run delay, binned into a log2 histogram.
def tracepoint__sched__sched_wakeup(pid)
  lat_start(pid)
  0
end

def tracepoint__sched__sched_switch(prev_pid, next_pid)
  d = lat_end(next_pid)
  if d > 0
    hist_observe(d)
  end
  0
end
