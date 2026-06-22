# USER_RINGBUF host→kernel command channel.
#
# Userspace pushes __u64 commands into bpf_user_cmds (the per-unit
# USER_RINGBUF). On every XDP packet the BPF program drains the queue and
# invokes the static callback emitted from `user_ringbuf__cmd_handler`.
# The callback updates per-unit counters and emits each command value via
# spnl_emit so userspace can correlate.
#
# Build:
#   spinel-ebpf compile examples/observability/user_ringbuf_demo.rb \
#       -o build/user_ringbuf_demo --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/user_ringbuf_demo/user_ringbuf_demo &
#   # Push commands with bpftool (8-byte records):
#   bpftool map update name bpf_user_cmds key 0 0 0 0 value 2a 0 0 0 0 0 0 0
#   # ... actually bpftool can't easily reserve+submit on USER_RINGBUF,
#   # so the production path is via a libbpf-using userspace client.
#   ping -c 5 127.0.0.1
#   bpftool map dump name user_ringbuf_d_top_cmds_received

@cmds_received = 0
@last_value = 0

# The body becomes the body of a static C callback invoked once per
# drained USER_RINGBUF record. The `value` arg is filled from the first 8
# bytes of the record via bpf_dynptr_read.
def user_ringbuf__cmd_handler(value)
  @cmds_received = @cmds_received + 1
  @last_value = value
  spnl_emit(value)
end

# Any BPF program can drain. We attach to XDP so each incoming packet
# triggers drain. In production you'd typically attach to a low-rate hook
# (sched_switch tracepoint, periodic tracepoint, ...) so drain happens
# regardless of network traffic.
def xdp__drain_user_ringbuf
  user_ringbuf_drain
  XDP::PASS
end

puts "user_ringbuf attached. Push commands via libbpf user-ringbuf API."
sleep 3600
