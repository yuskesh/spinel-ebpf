# `on :user_cmd do |cmd| ... end` in BPF::EventLoop. Userspace pushes
# 8-byte commands into the bpf_user_cmds USER_RINGBUF; the kernel-side
# callback (synthesized as `user_ringbuf__cmd_handler`) drains them via
# `user_ringbuf_drain` invoked from the colocated XDP handler.
#
# Build:
#   spinel-ebpf compile examples/observability/user_cmd_event_loop.rb \
#       -o build/user_cmd_event_loop --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/user_cmd_event_loop/user_cmd_event_loop &
#   # Push records into bpf_user_cmds via libbpf user-ringbuf API
#   # (bpftool can't reserve+submit on USER_RINGBUF).
#   ping -c 5 -q 127.0.0.1   # fires user_ringbuf_drain inside the XDP handler

@cmds_received = 0
@last_value    = 0
@xdp_count     = 0

module CmdChannel
  include BPF::EventLoop

  # Block param `cmd` is extracted via BlockParametersNode →
  # ParametersNode walk in the codegen's AST fallback path.
  on :user_cmd do |cmd|
    @cmds_received = @cmds_received + 1
    @last_value    = cmd
    spnl_emit(cmd)
  end

  # For now the user has to manually drain in some active hook.
  # Future work: auto-drain — partition could inject
  # `user_ringbuf_drain` into a designated handler.
  on :xdp do
    @xdp_count = @xdp_count + 1
    user_ringbuf_drain
    XDP::PASS
  end
end

puts "CmdChannel loaded — user_cmd handler + XDP drain in 1 module"
sleep 3600
