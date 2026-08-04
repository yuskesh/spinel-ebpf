# Every key of the common filter at once.
#
# Pins the maximal shape of spnl_filter_discard(): pid and tid share one
# bpf_get_current_pid_tgid(), uid and gid share one bpf_get_current_uid_gid()
# (the same grouping Inspektor Gadget's include/gadget/filter.h uses), cgroup_id
# and comm stand alone. Each group is guarded by "is any key in it set", which is
# what lets the verifier drop the helper call and not just the comparison.
#
# uid/gid are unset at -1, not 0: uid 0 is root and has to be selectable.
#
# The body reads the uid/gid builtins the filter is built on. They exist so the
# filter is a shorthand and not a black box -- `filter_by :uid` hides exactly the
# guard an author could have written by hand as `if uid == target_uid`.
filter_by :pid, :tid, :uid, :gid, :cgroup_id, :comm

def spnl_emit(x)
  # placeholder (builtin)
end

def kprobe__do_sys_openat2(dfd)
  spnl_emit(uid + gid)
  0
end
