# skb-rewrite builtins (TC) — skb_load_byte / skb_store_byte /
# l3_csum_replace. IPv4 TTL decrement + checksum fix.
@n = 0

def tc__egress__ttl
  ttl = skb_load_byte(22)
  if ttl > 1
    nt = ttl - 1
    l3_csum_replace(24, ttl << 8, nt << 8)
    skb_store_byte(22, nt)
    @n = @n + 1
  end
  TC_ACT_OK
end
