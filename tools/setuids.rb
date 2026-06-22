# setuids — trace setuid/setresuid calls (bcc setuids equivalent).
#
# Streams the target uid(s): setuid -> the single uid; setresuid -> (ruid, euid,
# suid). Useful for spotting privilege changes (logins, su, daemons dropping
# privs).
#
#   bin/spinel-ebpf compile tools/setuids.rb --build -o build/setuids
#   sudo ./build/setuids/setuids   # streams: <ktime> <uid>  /  <ktime> <r> <e> <s>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_setuid(uid)
  spnl_emit(uid)
  0
end

def tracepoint__syscalls__sys_enter_setresuid(ruid, euid, suid)
  spnl_emit3(ruid, euid, suid)
  0
end

puts "[setuids] setuid uid / setresuid (ruid euid suid):"
Stream.spnl_stream(0)
