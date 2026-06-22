# runqslower — report run-queue waits over a threshold (bcc runqslower).
#
# Like runqlat but per-event: emit (pid, run-queue-latency) only when a task
# waited more than 1ms between wakeup and actually running.
#
#   bin/spinel-ebpf compile tools/runqslower.rb --build -o build/runqslower
#   sudo ./build/runqslower/runqslower    # streams: <ktime> <pid> <latency_ns>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sched__sched_wakeup(pid)
  lat_start(pid)
  0
end

def tracepoint__sched__sched_switch(prev_pid, next_pid)
  d = lat_end(next_pid)
  if d > 1000000          # > 1ms run-queue wait
    spnl_emit_pair(next_pid, d)
  end
  0
end

puts "[runqslower] ktime  pid  runq_latency_ns (> 1ms):"
Stream.spnl_stream(0)
