# Negative fixture: the fourth SEC.
#
# fexit/vfs_getattr, so that all four measured hooks (fentry and fexit, times
# dentry_open and vfs_getattr) have a committed refusal, not just a
# representative one.
@denied = 0

def fexit__vfs_getattr(path, stat, request_mask, query_flags, ret)
  if path_eq(path, "/etc/shadow")
    @denied = @denied + 1
  end
  0
end
