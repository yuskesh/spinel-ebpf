# killsnoop — trace signals sent via kill(2) (bcc killsnoop equivalent).
#
# sys_enter_kill(pid, sig) gives the target pid and signal number; we stream the
# pair. bcc killsnoop also shows the sender pid/comm (available via pid()/comm)
# — left out of this MVP for a clean (target_pid, signal) stream.
#
#   bin/spinel-ebpf compile tools/killsnoop.rb --build -o build/killsnoop
#   sudo ./build/killsnoop/killsnoop      # streams: <ktime> <target_pid> <signal>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_kill(pid, sig)
  spnl_emit_pair(pid, sig)
  0
end

puts "[killsnoop] ktime  target_pid  signal:"
Stream.spnl_stream(0)
