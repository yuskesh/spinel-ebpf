# Path-based policy on a security hook other than open.
#
# The path builtins (emit_path / path_eq / ...) used to be writable on three
# hooks only -- the file_open family -- because of bpf_d_path's kernel gate.
# Measuring the whole hook matrix on a 7.1.5 kernel showed the security_path_*
# family loads as well, so it joined the gate. Only hooks that were actually
# measured to load are in it; nothing is added by guessing.
#
# lsm/path_unlink's first argument is ALREADY a `struct path *`, so the file-form
# `&file->f_path` conversion must not be applied to it. What each hook hands over
# differs, and knowing that per hook is what the codegen has to get right.
#
# "Deny deletion under a given directory" is then a handful of Ruby.
@denied = 0
@allowed = 0

def lsm__path_unlink(dir, dentry)
  if path_eq(dir, "/etc/spnl_locked_dir")
    @denied = @denied + 1
    -1
  else
    @allowed = @allowed + 1
    0
  end
end
