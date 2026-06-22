# softirqs — soft IRQ handler time distribution (bcc softirqs equivalent).
#
# softirq_entry/exit bracket a softirq; like hardirqs we key the latency by
# cpu_id() and bin the handler durations into a log2 histogram.
#
#   bin/spinel-ebpf compile tools/softirqs.rb --build -o build/softirqs
#   sudo ./build/softirqs/softirqs        # samples 5s, then prints the histogram
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def tracepoint__irq__softirq_entry
  lat_start(cpu_id)
  0
end

def tracepoint__irq__softirq_exit
  d = lat_end(cpu_id)
  if d > 0
    hist_observe(d)
  end
  0
end

puts "[softirqs] measuring soft IRQ handler time for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "softirq handler time (ns)")
