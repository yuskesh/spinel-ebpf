# USER_RINGBUF host->kernel command channel.
#
# The same source shape as the retired Ruby generator's own artefact (which is
# what the committed example examples/observability/user_ringbuf_demo.rb
# produced), so the golden can be compared directly against it.
#
# `def user_ringbuf__<name>(value)` is the one attach kind that emits no program:
# it becomes `static long spnl_user_ringbuf_cb_<name>(struct bpf_dynptr *, void *)`,
# which bpf_user_ringbuf_drain calls once per record the host pushed. The XDP
# handler below is the drain site -- choosing it is the author's job, because it
# sets how often commands are picked up.
#
# It was a negative fixture, named 143_user_ringbuf_withdrawn, while the attach
# kind stood withdrawn.
@cmds_received = 0
@last_value = 0

def user_ringbuf__cmd_handler(value)
  @cmds_received = @cmds_received + 1
  @last_value = value
  spnl_emit(value)
end

def xdp__drain_user_ringbuf
  user_ringbuf_drain
  XDP_PASS
end
