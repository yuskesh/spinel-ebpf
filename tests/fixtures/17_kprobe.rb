def spnl_emit(x)
  # placeholder
end

# Method-name conventions handled by spinel-ebpf codegen:
#   kprobe__<target>             -> SEC("kprobe/<target>")     ctx=struct pt_regs *
#   kretprobe__<target>          -> SEC("kretprobe/<target>")  ctx=struct pt_regs *
#   tracepoint__<cat>__<name>    -> SEC("tracepoint/<cat>/<name>")  ctx=void *
#
# Tracepoint chosen over kprobe for portability: kprobe target names move
# between kernel versions / configs, tracepoints are part of the stable
# kernel ABI. sys_enter_openat fires for every openat() syscall.
def tracepoint__syscalls__sys_enter_openat
  spnl_emit(1)
end
