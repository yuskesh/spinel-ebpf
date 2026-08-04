# Look at a path on the hook that fires on exec (the `struct linux_binprm *` form).
#
# lsm/bprm_check_security is handed a binprm, so the path is two hops away
# (`bprm->file->f_path`). Walking it with a DIRECT deref is the point:
# BPF_CORE_READ returns a scalar, and bpf_d_path wants a trusted pointer, so the
# scalar cannot be passed to it.
#
# The NULL guard is fail-safe -- an unknown path is a non-match, the same policy
# path_eq applies everywhere else.
#
# "Deny the exec of this binary" plus "record what was exec'd".
@denied = 0

def lsm__bprm_check_security(bprm)
  emit_path(bprm)
  if path_eq(bprm, "/usr/bin/spnl_denied_exec")
    @denied = @denied + 1
    -1
  else
    0
  end
end
