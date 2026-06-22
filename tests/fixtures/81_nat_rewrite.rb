# NAT builtins (TC) — skb_load_u32 / skb_store_u32 + l3/l4_csum_replace_ip.
# IPv4 DNAT: rewrite dst 10.0.0.2 -> 10.0.0.99, fix IP + TCP (pseudo-hdr) csums.
@n = 0

def tc__ingress__dnat
  dst = skb_load_u32(30)
  if dst == 167772162
    new = 167772259
    l3_csum_replace_ip(24, dst, new)
    l4_csum_replace_ip(50, dst, new)
    skb_store_u32(30, new)
    @n = @n + 1
  end
  TC_ACT_OK
end
