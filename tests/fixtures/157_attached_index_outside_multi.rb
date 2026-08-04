# attached_index called in a one-to-one handler.
#
# There the attach point is the method name, so there is nothing to ask about --
# refuse rather than answer a constant 0.
def kprobe__vfs_read
  @n = @n + attached_index
  0
end
