# execsnoop — trace new processes (execve) with their full argv (bcc execsnoop).
#
# On sys_enter_execve we stream the program path (filename) and every argv[]
# element. emit_argv walks the user-space pointer array exactly like bcc's
# execsnoop, reading each arg string with bpf_probe_read_user_str.
#
#   bin/spinel-ebpf compile tools/execsnoop.rb --build -o build/execsnoop
#   sudo ./build/execsnoop/execsnoop        # streams: <ktime> <path/arg>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_execve(filename, argv)
  spnl_emit_str(filename)
  emit_argv(argv)
  0
end

puts "[execsnoop] tracing execve (path + argv):"
Stream.spnl_stream(0)
