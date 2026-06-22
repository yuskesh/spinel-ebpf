# Stateful L4 load balancer v2 — the backend pool is an arena-resident
# "selection ring" that userspace builds and maintains. This adds three things
# to the basic load balancer with ZERO new codegen, all by composition:
#
#   - map-ified pool: backends live in arena slots 0..15, written by
#     userspace via mmap instead of hardcoded in Ruby.
#   - weighted: userspace replicates each backend IP into the ring proportional
#     to its weight (e.g. A x8, B x4, ...), so a flow that lands on more slots is
#     more likely to pick that backend.
#   - health check: userspace drops an unhealthy backend from the ring (0 slots),
#     so new flows stop going to it.
#
# BPF just hashes the flow into a ring slot and reads the backend IP. Stickiness
# (conntrack) keeps an established flow on its backend. The VIP is 10.0.0.2.
@rewrites = 0

def tc__ingress__lb
  bip = flow_get(:conn, :backend_ip)     # conntrack: 0 on a new flow
  if bip == 0
    idx = skb_load_u16(34) & 15          # source port -> ring slot (16-entry ring)
    bip = arena_get(idx)                 # backend IP from the userspace-managed ring
    flow_set(:conn, :backend_ip, bip)    # sticky
    @rewrites = @rewrites + 1
  end
  old = skb_load_u32(30)
  l3_csum_replace_ip(24, old, bip)
  l4_csum_replace_ip(50, old, bip)
  skb_store_u32(30, bip)
  TC_ACT_OK
end

puts "tc_l4_lb_pool loaded (userspace fills the arena backend ring)"
sleep 3600
