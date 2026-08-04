# The codegen must REJECT this.
#
# `default:` is baked into .rodata by the compiler, so it has to be an integer
# literal. A string (or any expression) cannot be evaluated at compile time, and
# the only thing worse than refusing it would be quietly substituting 0 -- which
# for a filter parameter is the value that means "off".
#
# There is no golden for this fixture; the refusal is the contract.
param :min_size, default: "large"

def spnl_emit(x)
  # placeholder (builtin)
end

def tracepoint__syscalls__sys_enter_openat(dfd)
  if dfd >= min_size
    spnl_emit(dfd)
  end
  0
end
