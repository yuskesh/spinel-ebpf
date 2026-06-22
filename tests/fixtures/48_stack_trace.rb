# stack_id() / user_stack_id() smoke fixture.
# Captures both kernel + user stacks at openat entry, bins by stack id.

def kprobe__do_sys_openat2(dfd, filename)
  ksid = stack_id
  usid = user_stack_id
  hist_observe_by(ksid, 1)
  spnl_emit_pair(ksid, usid)
end
