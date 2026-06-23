# Kernel load-check: kprobe counter (tracing).
#
# Increments a counter on every openat(2). Exercises kprobe attachment,
# probe arguments, and PT_REGS_PARM extraction -- which needs the BPF target
# arch macro that the harness passes to clang.
@opens = 0
def kprobe__do_sys_openat2(dfd, filename)
  @opens += 1
end
