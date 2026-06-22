# biolatency — block I/O latency histogram (bcc biolatency equivalent).
#
# Times each block request from dispatch (blk_mq_start_request) to completion
# (blk_mq_end_request), keyed by the request pointer (PARM1, the same struct on
# both probes), and bins the service time into a log2 histogram.
#
#   bin/spinel-ebpf compile tools/biolatency.rb --build -o build/biolatency
#   sudo ./build/biolatency/biolatency &
#   dd if=/dev/zero of=/f bs=1M count=50 conv=fsync     # generate device I/O
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def kprobe__blk_mq_start_request(rq)
  lat_start(rq)
  0
end

def kprobe__blk_mq_end_request(rq)
  d = lat_end(rq)
  if d > 0
    hist_observe(d)
  end
  0
end

puts "[biolatency] measuring block I/O latency for 6s..."
sleep 6
Hist.spnl_dump_log2_hist("bpf_hist", "block I/O latency (ns)")
