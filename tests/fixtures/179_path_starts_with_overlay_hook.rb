# Negative fixture: the PREFIX selector on the other overlayfs-internal hook.
#
# Same finding as 178, different SEC and different selector. `fentry/vfs_getattr`
# is doubly misleading: stat(2) does not even reach it (stat goes through
# vfs_getattr_nosec -- ftrace measured 79 hits against 0), and when overlayfs's
# copy-up does reach it the path is rendered `/f`. Prefix matching is if anything
# worse than exact matching here, because `/f` starts with `/` and any prefix
# short enough to survive the rendering matches everything.
@hits = 0

def fentry__vfs_getattr(path, stat, request_mask, query_flags)
  if path_starts_with(path, "/etc/")
    @hits = @hits + 1
  end
  0
end
