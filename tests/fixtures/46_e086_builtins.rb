# divu / comm_hash / emit_comm smoke fixture.

def kprobe__do_sys_openat2(dfd, filename)
  # bin a fixed value via divu for verifier exercise
  hist_observe_linear(divu(ktime_ns, 1000))
  emit_comm
end

def kretprobe__do_sys_openat2(ret)
  spnl_emit(comm_hash)
end
