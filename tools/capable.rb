# capable — trace capability checks (bcc capable equivalent).
#
# kprobe cap_capable(cred, ns, cap, opts): the 3rd arg is the capability number
# being checked (CAP_* — e.g. 13=CAP_NET_RAW, 23=CAP_SYS_NICE). We stream the
# cap number and the checked process's comm.
#
#   bin/spinel-ebpf compile tools/capable.rb --build -o build/capable
#   sudo ./build/capable/capable     # streams: <ktime> <cap> then <ktime> <comm>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__cap_capable(cred, ns, cap)
  spnl_emit(cap)
  emit_comm
  0
end

puts "[capable] cap-number + comm of capability checks:"
Stream.spnl_stream(0)
