# An empty symbol list. A handler attached to nothing is a program that loads and
# never fires, which is exactly the silent no-op this codegen refuses to emit.
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[] do
    @n = @n + 1
  end
end
