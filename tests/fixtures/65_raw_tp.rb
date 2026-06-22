# raw tracepoint — lower-overhead tracepoint with raw args. Counts every
# syscall entry via the raw sys_enter tracepoint. Auto-attached by libbpf.
@syscalls = 0
def raw_tp__sys_enter
  @syscalls = @syscalls + 1
end
