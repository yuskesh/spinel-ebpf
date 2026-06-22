# mountsnoop — trace mount(2) / umount(2) calls (bcc mountsnoop equivalent).
#
# sys_enter_mount's 2nd arg is the target dir (mount point); sys_enter_umount's
# 1st arg is the target. We stream the path via the str ringbuf.
#
#   bin/spinel-ebpf compile tools/mountsnoop.rb --build -o build/mountsnoop
#   sudo ./build/mountsnoop/mountsnoop    # streams: <ktime> <path>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_mount(dev_name, dir_name)
  spnl_emit_str(dir_name)
  0
end

def tracepoint__syscalls__sys_enter_umount(name)
  spnl_emit_str(name)
  0
end

puts "[mountsnoop] mount/umount target paths:"
Stream.spnl_stream(0)
