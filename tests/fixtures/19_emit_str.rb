def spnl_emit(x)
  # placeholder
end

def spnl_emit_str(p)
  # placeholder; codegen replaces with bpf_probe_read_user_str + ringbuf submit
end

# Observe each openat: emit dfd (int) AND the filename (string).
# Demonstrates that one tracepoint can produce two event kinds on different
# per-unit ringbufs.
def tracepoint__syscalls__sys_enter_openat(dfd, filename)
  spnl_emit(dfd)
  spnl_emit_str(filename)
end
