# hardirqs — hard IRQ handler time distribution (bcc hardirqs equivalent).
#
# irq_handler_entry/exit bracket a hard IRQ handler; it runs to completion on
# one CPU, so cpu_id() is a collision-free key for the latency. The handler
# durations are binned into a log2 histogram.
#
#   bin/spinel-ebpf compile tools/hardirqs.rb --build -o build/hardirqs
#   sudo ./build/hardirqs/hardirqs        # samples 5s, then prints the histogram
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def tracepoint__irq__irq_handler_entry
  lat_start(cpu_id)
  0
end

def tracepoint__irq__irq_handler_exit
  d = lat_end(cpu_id)
  if d > 0
    hist_observe(d)
  end
  0
end

puts "[hardirqs] measuring hard IRQ handler time for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "hardirq handler time (ns)")
