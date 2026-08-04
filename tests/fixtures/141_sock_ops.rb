# SOCK_OPS -- cgroup-scoped TCP state observation.
#
# This attach kind was measured SILENT: `def sock_ops__<name>` compiled with
# exit 0 into a plain SEC("syscall") wrapper (byte-identical to a method with no
# attach prefix), so the program loaded, attached to nothing and never fired.
# There was no fixture for it, which is exactly why nothing noticed -- a golden
# gate compares text, and text you never generate cannot differ.
#
# The two ctx readers are the point of the kind: `sock_ops_op` is the
# BPF_SOCK_OPS_* event code (ctx->op) and `sock_ops_state` is the new TCP state
# in a STATE_CB (ctx->args[1]). Without them a sockops program can only count.
#
# The wrapper does NOT propagate the inner's value: a sockops return is not a
# verdict (the same rule the Ruby oracle applied). Attach is cgroup-scoped and
# the glue does it from $SPNL_CGROUP_PATH.
@active_connects = 0
@established = 0

def sock_ops__main
  op = sock_ops_op
  if op == BPF::SockOps::TCP_CONNECT_CB
    @active_connects = @active_connects + 1
  end
  if op == BPF::SockOps::STATE_CB
    if sock_ops_state == TCP_STATE_ESTABLISHED
      @established = @established + 1
    end
  end
  0
end
