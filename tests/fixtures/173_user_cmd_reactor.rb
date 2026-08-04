# The reactor spelling of the same channel.
#
# `on :user_cmd do |cmd| ... end` synthesizes the flat name
# `user_ringbuf__cmd_handler`, and the block parameter is extracted through the
# BlockParametersNode -> ParametersNode hop. The colocated `on :xdp` is the drain
# site, exactly as in the flat fixture 143.
#
# DECLARATION ORDER IS DELIBERATE HERE: the drain is written ABOVE the callback.
# The retired Ruby generator learned the callback's name while emitting it, so
# this order died -- which is why examples/observability/full_observability_demo.rb
# still carries a comment telling the author to put `on :user_cmd` first. The C
# generator learns the name in the pre-scan instead, so the order no longer
# matters.
@xdp_count     = 0
@cmds_received = 0
@last_value    = 0

module CmdChannel
  include BPF::EventLoop

  on :xdp do
    @xdp_count = @xdp_count + 1
    user_ringbuf_drain
    XDP::PASS
  end

  on :user_cmd do |cmd|
    @cmds_received = @cmds_received + 1
    @last_value    = cmd
  end
end
