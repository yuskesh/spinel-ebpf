# cpudist — on-CPU time distribution per scheduling slice (bcc cpudist equivalent).
#
# On each context switch, the outgoing task (prev_pid) ran since it was last
# switched in; lat_end(prev_pid) is that on-CPU time, binned into a log2
# histogram. lat_start(next_pid) marks the incoming task starting to run.
#
#   bin/spinel-ebpf compile tools/cpudist.rb --build -o build/cpudist
#   sudo ./build/cpudist/cpudist          # samples 5s, then prints the histogram
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def tracepoint__sched__sched_switch(prev_pid, next_pid)
  d = lat_end(prev_pid)       # prev ran until now -> on-CPU time
  if d > 0
    hist_observe(d)
  end
  lat_start(next_pid)         # next starts running now
  0
end

puts "[cpudist] measuring on-CPU time per slice for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "on-CPU time (ns)")
