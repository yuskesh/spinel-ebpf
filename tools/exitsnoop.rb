# exitsnoop — trace process exits (bcc exitsnoop equivalent).
#
# sched:sched_process_exit fires in the exiting task's context, so we stream its
# pid and comm (bpf_get_current_comm). bcc exitsnoop also shows the exit code;
# that isn't a scalar tracepoint field, so this MVP reports pid + name.
#
#   bin/spinel-ebpf compile tools/exitsnoop.rb --build -o build/exitsnoop
#   sudo ./build/exitsnoop/exitsnoop      # streams: <ktime> <pid> then <ktime> <comm>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__sched__sched_process_exit(pid)
  spnl_emit(pid)
  emit_comm
  0
end

puts "[exitsnoop] exiting pid + comm:"
Stream.spnl_stream(0)
