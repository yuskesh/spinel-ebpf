# The same body as 153_attach_multi_expand, carried on kprobe_multi (via: :multi).
#
# The `_inner` it generates is byte-identical to 153's; only the wrapper changes
# (a literal index becomes bpf_get_attach_cookie).
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write], via: :multi do
    @calls = @calls + 1
    if attached_symbol_eq("vfs_read")
      @reads = @reads + 1
    end
    spnl_emit(attached_index)
  end
end
