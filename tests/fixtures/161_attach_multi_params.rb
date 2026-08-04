# Block params on a multi-symbol handler.
#
# The attach-kind table declares the args as "PT_REGS_PARM<N>(ctx) -- same as
# kprobe", but kprobe_multi is fprobe-backed, so that is a claim about the KERNEL
# rather than about this codegen; it was measured under both lowerings
# (calls=50 / buf_nonzero=50). What the golden pins here is that
# <bpf/bpf_tracing.h> is included -- leaving it out makes clang, not the codegen,
# fail with `PT_REGS_PARM2` undeclared, which is what happened first.
module A
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write], via: :multi do |file, buf|
    @calls = @calls + 1
    if buf > 0
      @nonzero = @nonzero + 1
    end
  end
end
