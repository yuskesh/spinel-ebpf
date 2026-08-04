# Runtime parameters.
#
# `param :name, default: N` is a top-level declaration, not a call: the codegen
# turns it into `volatile const __s64 spnl_param_<name> = N;` in .rodata and the
# loader patches it between skeleton __open() and __load(). The same binary can
# then be narrowed with SPNL_PARAM_TARGET_PID=<pid> instead of being recompiled.
#
# Unset (= the default 0) is not "the filter runs and always passes": .rodata is
# frozen before load, so the verifier knows the value and removes the guard from
# the program it accepts. Measured with `bpftool prog dump xlated`.
param :target_pid, default: 0
param :min_dfd

def spnl_emit(x)
  # placeholder (builtin)
end

def tracepoint__syscalls__sys_enter_openat(dfd)
  if (target_pid == 0 || pid == target_pid) && dfd >= min_dfd
    @opens += 1
    spnl_emit(dfd)
  end
  0
end
