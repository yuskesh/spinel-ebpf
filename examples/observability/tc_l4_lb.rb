# A stateful L4 load balancer, written in Ruby — the capstone that composes
# the datapath builtins with ZERO new codegen:
#   - conntrack: flow_get/flow_set (LRU_HASH keyed by the TCP 4-tuple)
#   - backend selection: hash the source port into 4 backends (& 3, no signed mod)
#   - DNAT: skb_load_u32 + l3/l4_csum_replace_ip + skb_store_u32
#
# For a new flow we pick a backend and remember it in the conntrack map, so every
# later packet of the same flow is rewritten to the SAME backend (stickiness).
# Incoming packets are addressed to the VIP 10.0.0.2; we DNAT the dst to one of
# 10.0.0.101..104. Offsets assume IPv4/TCP with no IP options.
#
# Verified with BPF_PROG_TEST_RUN.
@new_flows = 0

def tc__ingress__lb
  bip = flow_get(:conn, :backend_ip)     # 0 on a new flow (LRU_HASH miss)
  if bip == 0
    idx = skb_load_u16(34) & 3           # source port -> backend 0..3
    if idx == 0
      bip = 167772261                    # 10.0.0.101
    elsif idx == 1
      bip = 167772262                    # 10.0.0.102
    elsif idx == 2
      bip = 167772263                    # 10.0.0.103
    else
      bip = 167772264                    # 10.0.0.104
    end
    flow_set(:conn, :backend_ip, bip)    # remember -> sticky
    @new_flows = @new_flows + 1
  end
  old = skb_load_u32(30)                  # current dst (the VIP)
  l3_csum_replace_ip(24, old, bip)        # fix IP header csum
  l4_csum_replace_ip(50, old, bip)        # fix TCP csum (pseudo-header)
  skb_store_u32(30, bip)                  # DNAT dst -> backend
  TC_ACT_OK
end

puts "tc_l4_lb loaded (SPNL_TCX_IFACE=lo)"
sleep 3600
