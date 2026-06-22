# syncsnoop — trace sync(2) family calls (bcc syncsnoop).
#
# Streams the pid that invoked sync / fsync / fdatasync. bcc syncsnoop flags
# applications forcing writeback; the calling pid identifies the culprit.
#
#   bin/spinel-ebpf compile tools/syncsnoop.rb --build -o build/syncsnoop
#   sudo ./build/syncsnoop/syncsnoop      # streams: <ktime> <pid>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_sync
  spnl_emit(pid)
  0
end

def tracepoint__syscalls__sys_enter_fsync(fd)
  spnl_emit(pid)
  0
end

def tracepoint__syscalls__sys_enter_fdatasync(fd)
  spnl_emit(pid)
  0
end

puts "[syncsnoop] pid calling sync/fsync/fdatasync:"
Stream.spnl_stream(0)
