# stateful L4 load balancer — conntrack (flow_get/set) + port-hash backend
# selection + DNAT (csum repair). Pure composition of existing builtins.
@new_flows = 0

def tc__ingress__lb
  bip = flow_get(:conn, :backend_ip)
  if bip == 0
    idx = skb_load_u16(34) & 3
    if idx == 0
      bip = 167772261
    elsif idx == 1
      bip = 167772262
    elsif idx == 2
      bip = 167772263
    else
      bip = 167772264
    end
    flow_set(:conn, :backend_ip, bip)
    @new_flows = @new_flows + 1
  end
  old = skb_load_u32(30)
  l3_csum_replace_ip(24, old, bip)
  l4_csum_replace_ip(50, old, bip)
  skb_store_u32(30, bip)
  TC_ACT_OK
end
