# Negative fixture: the two SO_REUSEPORT selection builtins outside an
# SO_REUSEPORT selection program.
#
# `sk_reuseport` shares its AttachKind with sk_msg, sk_skb, socket_filter,
# flow_dissector, sk_lookup and the two cgroup sock_addr hooks, and every one of
# those has a different ctx struct -- so the gate is on the hook NAME, not on
# the kind.
#
# Without the gate this is a clang error two layers down: `struct xdp_md` has no
# member named `hash`, and bpf_sk_select_reuseport's first parameter is a
# `struct sk_reuseport_md *`. Neither message names the hook the author chose.

@picked = 0

def xdp__steer
  idx = reuseport_hash % 4
  worker_select(idx)
  @picked = @picked + 1
  XDP_PASS
end
