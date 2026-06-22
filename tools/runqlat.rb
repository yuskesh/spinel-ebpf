# runqlat — run-queue latency histogram (bcc runqlat equivalent).
#
# Time from when a task is woken (sched_wakeup) to when it actually runs
# (sched_switch picks it as next). lat_start(pid) stamps the wakeup keyed by the
# woken pid; lat_end(next_pid) on context switch yields the run-queue delay,
# binned into a log2 histogram.
#
#   bin/spinel-ebpf compile tools/runqlat.rb --build -o build/runqlat
#   sudo ./build/runqlat/runqlat        # samples 5s, then prints the histogram
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

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

puts "[runqlat] measuring run-queue latency for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "run queue latency (ns)")
