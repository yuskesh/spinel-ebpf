# L4 LB v2 — backend pool as an arena selection ring (map-ified + weighted
# + health, all managed by userspace). conntrack + arena_get + DNAT, zero new codegen.
@rewrites = 0

def tc__ingress__lb
  bip = flow_get(:conn, :backend_ip)
  if bip == 0
    idx = skb_load_u16(34) & 15
    bip = arena_get(idx)
    flow_set(:conn, :backend_ip, bip)
    @rewrites = @rewrites + 1
  end
  old = skb_load_u32(30)
  l3_csum_replace_ip(24, old, bip)
  l4_csum_replace_ip(50, old, bip)
  skb_store_u32(30, bip)
  TC_ACT_OK
end
