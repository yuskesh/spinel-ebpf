# POSITIVE fixture: the other half of the asymmetric gate.
#
# The same SEC that 178 refuses. `emit_path` records whatever this hook hands you
# -- which is the honest use: "overlayfs copied a file up" is a real event and
# the rendered `/f` is a real string. `parent_path_eq` is allowed too, and for a
# different reason: its path comes from the TASK chain
# (real_parent->mm->exe_file->f_path), not from this hook's argument, so the
# rendering finding does not reach it at all.
#
# Committing this is the point: a gate that refused the whole hook would look
# identical in every "N refusals" count, and this fixture is what makes the two
# distinguishable.
@copyups = 0

def fentry__dentry_open(path, flags, cred)
  @copyups = @copyups + 1
  emit_path(path)
  if parent_path_eq("/usr/bin/ovl")
    @copyups = @copyups + 1
  end
  0
end
