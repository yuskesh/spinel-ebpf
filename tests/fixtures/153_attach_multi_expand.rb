# One definition -> many attach points, expanded (via: :expand).
#
# The body is written one way only, through `attached_symbol_eq` /
# `attached_index`; which lowering was chosen is invisible from it. Paired with
# 154_attach_multi_multi, the fact that the `_inner` of those two goldens agree
# is the standing evidence that the body really is written one way.
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write], via: :expand do
    @calls = @calls + 1
    if attached_symbol_eq("vfs_read")
      @reads = @reads + 1
    end
    spnl_emit(attached_index)
  end
end
