# An unknown `via:`. Falling back to auto without a word would read as "I asked
# for it and it did nothing", so it is refused.
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write], via: :kprobe_multi do
    @n = @n + 1
  end
end
