# attached_symbol_eq called with a name that was never declared.
#
# The negative control for refusing at compile time instead of folding it into
# "a constant that can never match".
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write] do
    if attached_symbol_eq("vfs_open")
      @n = @n + 1
    end
  end
end
