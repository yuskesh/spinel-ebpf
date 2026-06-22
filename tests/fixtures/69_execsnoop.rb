# trace execve with full argv (bcc execsnoop). emit_argv walks the
# user-space argv[] pointer array and emits each element as a string event.
def tracepoint__syscalls__sys_enter_execve(filename, argv)
  spnl_emit_str(filename)
  emit_argv(argv)
  0
end
