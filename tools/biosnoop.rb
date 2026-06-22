# biosnoop — per-I/O block trace with latency (bcc biosnoop equivalent).
#
# Unlike biolatency's histogram, biosnoop streams one line per block I/O. We key
# the latency by the request pointer (blk_mq_start_request -> blk_mq_end_request)
# and, at completion, read the request's sector and byte count via kfield
# (BPF_CORE_READ), emitting (sector, bytes, latency_ns).
#
#   bin/spinel-ebpf compile tools/biosnoop.rb --build -o build/biosnoop
#   sudo ./build/biosnoop/biosnoop    # streams: <ktime> <sector> <bytes> <latency_ns>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__blk_mq_start_request(rq)
  lat_start(rq)
  0
end

def kprobe__blk_mq_end_request(rq)
  d = lat_end(rq)
  if d > 0
    sector = kfield(rq, "request", "__sector")
    bytes = kfield(rq, "request", "__data_len")
    spnl_emit3(sector, bytes, d)
  end
  0
end

puts "[biosnoop] ktime  sector  bytes  latency_ns (per block I/O):"
Stream.spnl_stream(0)
