def spnl_emit(x)
  # placeholder
end

# Tracepoint with named-field extraction. Block param names must match
# the kernel struct field names of trace_event_raw_sched_switch.
# Each context switch emits the prev_pid (the task being switched out).
def tracepoint__sched__sched_switch(prev_pid, next_pid)
  spnl_emit(prev_pid)
end
