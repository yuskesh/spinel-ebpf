# statsnoop — trace stat(2) family calls with their path (bcc statsnoop).
#
# Modern glibc stat() routes through newfstatat / statx; both take the path as
# the 2nd syscall arg. We stream it via the str ringbuf.
#
#   bin/spinel-ebpf compile tools/statsnoop.rb --build -o build/statsnoop
#   sudo ./build/statsnoop/statsnoop      # streams: <ktime> <path>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_newfstatat(dfd, filename)
  spnl_emit_str(filename)
  0
end

def tracepoint__syscalls__sys_enter_statx(dfd, filename)
  spnl_emit_str(filename)
  0
end

puts "[statsnoop] stat'd paths:"
Stream.spnl_stream(0)
