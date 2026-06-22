def spnl_emit(x)
  # placeholder
end

# Top-level ivar: persistent across attach handler invocations.
# Each openat() increments @open_count and emits the new value.
@open_count = 0

def tracepoint__syscalls__sys_enter_openat(dfd)
  @open_count = @open_count + 1
  spnl_emit(@open_count)
end
