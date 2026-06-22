# opensnoop — stream every open() with its filename (bcc opensnoop equivalent).
# The sys_enter_openat tracepoint emits the user-space path; the host streams
# each event (timestamp + filename) via the spnl_stream drain loop.
#
#   bin/spinel-ebpf compile tools/opensnoop.rb --build -o build/opensnoop
#   sudo ./build/opensnoop/opensnoop      # streams: <ktime_ns> <path>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_openat(dfd, filename)
  spnl_emit_str(filename)
end

puts "[opensnoop] tracing openat() filenames (timestamp_ns  path):"
Stream.spnl_stream(0)
