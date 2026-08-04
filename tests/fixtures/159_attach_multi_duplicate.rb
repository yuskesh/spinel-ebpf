# The same symbol twice in the list. Expanded it double-counts; as kprobe_multi
# libbpf rejects the whole link -- the behaviour diverges by lowering, so both
# refuse it alike.
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_read] do
    @n = @n + 1
  end
end
