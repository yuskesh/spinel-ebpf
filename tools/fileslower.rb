# fileslower — report VFS reads slower than a threshold (bcc fileslower).
#
# Times vfs_read with the tid-keyed latency helper; emits the latency only when
# a single read took more than 1ms (e.g. a blocking pipe/FIFO or a slow device).
#
#   bin/spinel-ebpf compile tools/fileslower.rb --build -o build/fileslower
#   sudo ./build/fileslower/fileslower    # streams: <ktime> <latency_ns>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__vfs_read
  latency_start
  0
end

def kretprobe__vfs_read(ret)
  d = latency_end
  if d > 1000000          # > 1ms
    spnl_emit(d)
  end
  0
end

puts "[fileslower] ktime  vfs_read_latency_ns (> 1ms):"
Stream.spnl_stream(0)
