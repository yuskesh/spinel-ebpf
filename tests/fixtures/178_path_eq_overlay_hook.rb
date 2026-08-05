# Negative fixture: a path SELECTOR on a hook whose path is not the caller's.
#
# `fentry/dentry_open` was measured end to end. It fires, bpf_d_path returns a
# real string -- and that string is rendered from OVERLAYFS'S INTERNAL MOUNT:
# `/f`, not the caller's `/tmp/ovd/low/f`. The control file in a different
# directory rendered to the same `/f`. A policy written this way matches the
# wrong file and there is no symptom: it compiles, it loads, it fires.
#
# That was first recorded as an affordance `caveat` -- prose that warns. Loud is
# better, and the codegen knows both facts at compile time (which builtin, and
# which SEC), so it refuses. Note what is NOT refused: emit_path in the same hook
# (fixture 182) -- recording what overlayfs copied up is honest; deciding on it
# is not.
@denied = 0

def fentry__dentry_open(path, flags, cred)
  if path_eq(path, "/etc/shadow")
    @denied = @denied + 1
  end
  0
end
