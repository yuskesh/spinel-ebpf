# emit_path(file) -- the full path of the opened file via bpf_d_path.
#
# bpf_d_path is kernel-gated (measured: lsm/file_open OK,
# fmod_ret/security_file_open OK, but lsm/file_permission REJECTED with
# "helper call is not allowed in probe"), so the codegen only permits the
# hooks that were actually measured to load (no silent fallback).
#
# The path lands on the per-unit string-event ringbuf, same channel as
# spnl_emit_str / emit_comm / emit_argv.
@opens = 0

def lsm__file_open(file, ret)
  @opens = @opens + 1
  emit_path(file)
  0
end

def fmod_ret__security_file_open(file, ret)
  emit_path(file)
  ret
end
