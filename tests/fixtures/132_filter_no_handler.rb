# NEGATIVE fixture: filter_by declared in a unit with no attach handler it can
# cover.
#
# The same rule that applies to an unread `param`: a switch wired to nothing is
# worse than no switch, because setting SPNL_FILTER_PID produces output identical
# to not setting it, and "the filter matched nothing" is indistinguishable from
# "the filter does not exist". `double` below is a plain method -- it becomes a
# SEC("syscall") entry point invoked by userspace through bpf_prog_test_run, not
# an event, so there is nothing there to narrow.
filter_by :pid, :comm

def double(x)
  x * 2
end
