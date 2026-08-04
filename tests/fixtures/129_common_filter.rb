# The in-kernel common filter.
#
# `filter_by` is a DECLARATION, not a call a handler makes. One line covers the
# whole unit: the codegen injects `if (spnl_filter_discard()) return 0;` at the
# head of every attach handler's entry wrapper. That is the point -- the failure
# this closes is not "the author wrote no filter", it is "the author wrote the
# filter in three handlers out of four", which every gate in this project passes
# (the channel balance report can say "nothing came out", never "the wrong
# things came out").
#
# Two handlers below, so the golden shows the injection is per-unit, not per-call.
# Unset keys are free: the verifier folds the guard away together with the
# bpf_get_current_* call inside it (measured with `bpftool prog dump xlated`).
filter_by :pid, :comm

def spnl_emit(x)
  # placeholder (builtin)
end

def kprobe__do_sys_openat2(dfd)
  @opens += 1
  spnl_emit(dfd)
  0
end

def tracepoint__syscalls__sys_enter_execve(filename)
  @execs += 1
  0
end
