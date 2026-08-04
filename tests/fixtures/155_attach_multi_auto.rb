# No `via:` = the codegen picks by list length. 2 < ATTACH_MULTI_THRESHOLD, so
# this expands. Moving that threshold changes this golden, and a change of
# lowering is not something that should happen quietly, so it is made visible
# here.
module FileOps
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write] do
    @calls = @calls + 1
  end
end
