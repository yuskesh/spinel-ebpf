def spnl_emit(x) ; end
def spnl_emit_pair(a, b)
  # placeholder; codegen replaces with ringbuf reserve/submit of pair event
end

def tracepoint__sched__sched_switch(prev_pid, next_pid)
  spnl_emit_pair(prev_pid, next_pid)
end
